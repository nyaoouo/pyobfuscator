"""Compare a schema4 final report with an independently supplied private build policy."""

import hashlib
import json
from typing import NamedTuple


class PrivateArgumentIdentity(NamedTuple):
    owner: str
    routing_tag: int
    domain: int
    owner_id: int


def _invalid(reason):
    raise ValueError(f"source-mixed private policy: {reason}")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("duplicate JSON object key")
        result[key] = value
    return result


def _number(value, nonzero=True):
    if type(value) is not int or value < int(nonzero) or value > 0xffffffff:
        _invalid("expected a bounded uint32")
    return value


def _identity(value):
    if type(value) is not str or not value:
        _invalid("expected a bounded identity")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as error:
        raise ValueError("source-mixed private policy: invalid identity encoding") from error
    if (size > 256 or
            any(ord(character) < 32 or ord(character) == 127 for character in value)):
        _invalid("expected a bounded identity")
    return value


def _fields(value, allowed, name):
    if type(value) is not dict or set(value) - allowed:
        _invalid(f"invalid {name} fields")
    return value


def _seed(domain, owner, name):
    # Mirror the public CFF component_seed; this is a tag, not key derivation.
    value = 2166136261 ^ domain
    for part in ("pyobf.cff.v1", owner, name):
        for byte in part.encode("utf-8"):
            value = ((value ^ byte) * 16777619) & 0xffffffff
        value = ((value ^ 0xff) * 16777619) & 0xffffffff
    return value


def _source_catalog(root):
    entries = root.get("sources")
    if type(entries) is not list or not 0 < len(entries) <= 256:
        _invalid("invalid source catalog")
    catalog = {}
    words = set()
    for index, entry in enumerate(entries):
        item = _fields(entry, {"id", "word_label", "group", "provider", "provider_version"},
                       "source catalog")
        name = _identity(item.get("id"))
        word = _number(item.get("word_label"))
        group = _identity(item.get("group"))
        provider = item.get("provider")
        if (provider not in ("owned-context-v1", "measured-scope-v1") or
                item.get("provider_version") != 1 or type(item.get("provider_version")) is not int or
                name in catalog or word in words):
            _invalid("invalid source catalog identity/provider")
        catalog[name] = (index, word, group, provider)
        words.add(word)
    return catalog


def _groups(rule, sources):
    entries = rule.get("groups", [])
    if type(entries) is not list or len(entries) > 256:
        _invalid("invalid required groups")
    counts = {}
    for source in sources:
        counts[source["group"]] = counts.get(source["group"], 0) + 1
    groups = []
    seen = set()
    for entry in entries:
        item = _fields(entry, {"id", "minimum", "independent_evidence"}, "required group")
        name = _identity(item.get("id"))
        minimum = _number(item.get("minimum"))
        if (name in seen or minimum > counts.get(name, 0) or
                item.get("independent_evidence", False) is not False):
            _invalid("invalid required group binding")
        seen.add(name)
        groups.append({"id": name, "minimum": minimum, "independent_evidence": False})
    return groups


def _sites(root, owner, catalog, maximum_sites):
    bindings = root.get("bindings")
    if type(bindings) is not dict or set(bindings) != {owner}:
        _invalid("binding owner differs from selected function")
    binding = _fields(bindings[owner], {"sites", "default"}, "owner binding")
    if "default" in binding:
        _invalid("schema4 needs explicit site rules")
    rules = binding.get("sites")
    if type(rules) is not dict or not 1 <= len(rules) <= maximum_sites:
        _invalid("schema4 needs one or two explicit sites" if maximum_sites == 2 else
                 "bounded schema4 needs one to eight explicit sites")
    labels = []
    for key in rules:
        if (type(key) is not str or not 1 <= len(key) <= 10 or
                not key.isascii() or not key.isdecimal() or
                str(_number(int(key))) != key):
            _invalid("site labels must be canonical nonzero uint32")
        labels.append(int(key))
    sites = []
    domains = {}
    for index, label in enumerate(sorted(labels)):
        rule = _fields(rules[str(label)], {"sources", "mixing_domain", "groups"}, "site rule")
        names = rule.get("sources")
        if type(names) is not list or not 2 <= len(names) <= 256:
            _invalid("source-mixed site needs measured and owned references")
        sources = []
        prior = -1
        measured = owned = 0
        for name in names:
            if type(name) is not str or name not in catalog:
                _invalid("site uses an unknown source")
            position, word, group, provider = catalog[name]
            if position <= prior:
                _invalid("source-mixed binding must follow catalog order")
            prior = position
            measured += provider == "measured-scope-v1"
            owned += provider == "owned-context-v1"
            sources.append({"id": name, "word_label": word, "encoding": 1,
                            "group": group, "provider": provider, "provider_version": 1,
                            "class": "referenced-evidence" if provider == "measured-scope-v1"
                                     else "authenticated-material",
                            "sharing": "owner-independent" if provider == "measured-scope-v1"
                                       else "context-material", "use": "required-binding"})
        if measured != 1 or owned < 1:
            _invalid("source-mixed site needs one measured and at least one owned reference")
        domain = _identity(rule.get("mixing_domain"))
        tag = _seed(root["domain"], owner, domain)
        if tag == 0:
            _invalid("mixing domain maps to zero")
        prior_domain = domains.setdefault(tag, (owner, domain))
        if prior_domain != (owner, domain):
            _invalid("mixing domain identity collision")
        sites.append({"index": index, "label": label, "mixing_domain": domain,
                      "mixing_domain_tag": tag, "provider": "source-mixed-v1",
                      "provider_version": 1, "sources": sources, "groups": _groups(rule, sources)})
    return sites


def check_source_mixed_private_policy(raw, report, maximum_sites=2):
    if type(maximum_sites) is not int or maximum_sites not in (2, 8):
        _invalid("unsupported site-count bound")
    try:
        root = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=lambda _: _invalid("invalid JSON constant"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("source-mixed private policy: invalid JSON") from error
    root = _fields(root, {"schema_version", "provider", "routing_tag", "domain",
                          "private_words", "owners", "sources", "bindings",
                          "root_scheme", "measured_private_words"}, "root")
    if type(root.get("schema_version")) is not int or root["schema_version"] != 4 or root.get("provider") != "source-mixed-v1":
        _invalid("unsupported schema/provider")
    routing_tag = _number(root.get("routing_tag"))
    root["domain"] = _number(root.get("domain"))
    words = root.get("private_words")
    if type(words) is not list or len(words) != 8:
        _invalid("expected eight private words")
    for word in words:
        _number(word, nonzero=False)
    if "root_scheme" in root or "measured_private_words" in root:
        if root.get("root_scheme") != "provider-split-v1":
            _invalid("provider-split root scheme is missing or unsupported")
        measured = root.get("measured_private_words")
        if type(measured) is not list or len(measured) != 8:
            _invalid("provider-split needs eight measured private words")
        for word in measured:
            _number(word, nonzero=False)
        if measured == words:
            _invalid("provider-split roots must be distinct")
    functions = report.get("functions") if type(report) is dict else None
    if type(functions) is not list:
        _invalid("missing compiler function rows")
    selected = [row for row in functions if type(row) is dict and row.get("selected") and
                type(row.get("runtime_contribution")) is dict and
                row["runtime_contribution"].get("scheme_version") == 4 and
                row["runtime_contribution"].get("provider") == "source-mixed-v1"]
    if len(selected) != 1:
        _invalid("needs exactly one selected schema4 source-mixed owner")
    owner = selected[0].get("function")
    if type(owner) is not str or not owner:
        _invalid("invalid selected owner")
    owners = root.get("owners")
    if type(owners) is not dict or set(owners) != {owner}:
        _invalid("private owner differs from selected function")
    owner_id = _number(owners[owner])
    sites = _sites(root, owner, _source_catalog(root), maximum_sites)
    proof = selected[0]["runtime_contribution"]
    if proof.get("private_input_sha256") != hashlib.sha256(raw).hexdigest():
        _invalid("raw input SHA-256 differs from compiler report")
    if proof.get("sites") != sites:
        _invalid("site/source/group/domain projection differs from compiler report")
    if (proof.get("query_count") != sum(len(site["sources"]) for site in sites) or
            proof.get("helper_counts") != {
                "owned-context-v1": sum(source["provider"] == "owned-context-v1"
                                        for site in sites for source in site["sources"]),
                "measured-scope-v1": len(sites)}):
        _invalid("source query totals differ from private policy")
    return PrivateArgumentIdentity(owner, routing_tag, root["domain"], owner_id)
