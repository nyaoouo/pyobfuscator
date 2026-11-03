"""Typed compiler helper edges; ordinary callees and symbol prefixes confer no ownership."""
from collections import deque
import json

from reference_plan import _object, _symbol, _unique

MAX_REPORT = 16 * 1024 * 1024
GENERATORS = ("call-frames", "external-calls", "constant-archive")


def _count(value):
    if type(value) is not int or not 0 <= value <= 65536:
        raise ValueError("generated ownership needs bounded actual counts")
    return value


def graph(source):
    if type(source) is not bytes or not 0 < len(source) <= MAX_REPORT:
        raise ValueError("generated ownership needs bounded immutable compiler-report bytes")
    report = json.loads(source, object_pairs_hook=_unique)
    if (type(report) is not dict or type(report.get("schema_version")) is not int or
            report["schema_version"] != 2 or type(report.get("functions")) is not list or
            not 0 < len(report["functions"]) <= 65536):
        raise ValueError("generated ownership requires the actual CFF compiler report")
    rows = {}
    for row in report["functions"]:
        if type(row) is not dict: raise ValueError("invalid compiler function ownership row")
        name = row.get("function")
        if type(name) is not str or not name or name in rows:
            raise ValueError("duplicate or missing compiler function ownership definition")
        if row.get("selected") is True and (row.get("retained") is not True or row.get("status") != "transformed"):
            raise ValueError("generated ownership requires complete compiler transformation")
        rows[name] = row
    declared = report.get("generated_ownership")
    _object(declared, ("schema_version", "verified", "edges"))
    if (type(declared["schema_version"]) is not int or declared["schema_version"] != 1 or
            declared["verified"] is not True or type(declared["edges"]) is not list or len(declared["edges"]) > 65536):
        raise ValueError("generated ownership requires verified compiler edges")
    edges, counts = [], {}
    for edge in declared["edges"]:
        _object(edge, ("owner", "helper", "component", "site"))
        owner, helper = _symbol(edge["owner"]), _symbol(edge["helper"])
        component, site = edge["component"], edge["site"]
        if (component not in GENERATORS or type(site) is not str or not 0 < len(site) <= 4096 or
                owner == helper or any(name not in rows or rows[name].get("selected") is not True or
                    rows[name].get("retained") is not True for name in (owner, helper))):
            raise ValueError("generated ownership lost an actual registered owner/helper/site")
        edges.append((owner, helper, component, site))
        counts[owner, component] = counts.get((owner, component), 0) + 1
    if len(set(edges)) != len(edges): raise ValueError("duplicate generated ownership edge")
    expected = []
    for name, row in rows.items():
        if row.get("generated") is True:
            if row.get("requested") is not False or row.get("generation_component") not in GENERATORS[:2]:
                raise ValueError("generated helper has an invalid compiler creation contract")
            expected.append((row.get("generated_owner"), name, row.get("generation_component"), row.get("generated_site")))
        archive = row.get("archive_sources")
        if archive is not None:
            if type(archive) is not dict or type(archive.get("helpers")) is not list:
                raise ValueError("archive helper ownership lacks actual source acquisitions")
            if _count(archive.get("acquisitions")) != len(archive["helpers"]) or _count(archive.get("complete_acquisitions")) != len(archive["helpers"]):
                raise ValueError("archive helper ownership is incomplete")
            for helper in archive["helpers"]:
                _object(helper, ("function", "acquisition", "source_id"))
                if (type(helper["source_id"]) is not str or not helper["source_id"] or
                        type(helper["acquisition"]) is not str or not helper["acquisition"].endswith(":" + helper["source_id"])):
                    raise ValueError("archive helper lost its original source")
                expected.append((name, helper["function"], "constant-archive", helper["acquisition"]))
            sources = archive.get("sources")
            if type(sources) is not list or any(type(entry) is not dict or type(entry.get("id")) is not str for entry in sources):
                raise ValueError("archive helper lacks original source obligations")
            if (len({entry["id"] for entry in sources}) != len(sources) or
                    {entry["id"] for entry in sources if entry.get("status") == "applied"} !=
                    {helper["source_id"] for helper in archive["helpers"]}):
                raise ValueError("archive helpers differ from original source obligations")
        components = row.get("components", [])
        if type(components) is not list: raise ValueError("invalid compiler helper component inventory")
        for component in GENERATORS[:2]:
            found = [part for part in components if type(part) is dict and part.get("component") == component]
            actual = counts.get((name, component), 0)
            if len(found) > 1 or (not found and actual) or (found and _count(found[0].get("applied")) != actual):
                raise ValueError("generated helpers differ from original compiler call obligations")
    if any(any(type(value) is not str for value in edge) for edge in expected):
        raise ValueError("invalid typed compiler helper/acquisition fields")
    if len(set(expected)) != len(expected) or set(expected) != set(edges):
        raise ValueError("generated ownership differs from typed compiler helper/acquisition inventory")
    successors = {name: set() for name in rows}
    degree = dict.fromkeys(rows, 0)
    for owner, helper, component, site in edges:
        if helper not in successors[owner]:
            successors[owner].add(helper); degree[helper] += 1
    ready = deque(name for name, count in degree.items() if not count)
    visited = 0
    while ready:
        name = ready.popleft(); visited += 1
        for helper in successors[name]:
            degree[helper] -= 1
            if not degree[helper]: ready.append(helper)
    if visited != len(rows): raise ValueError("generated ownership has a dependency cycle")
    return rows, tuple(sorted(edges))


def closure(rows, edges, root):
    if root not in rows or rows[root].get("retained") is not True:
        raise ValueError("selected generated ownership root is missing")
    found, pending = set(), [root]
    successors = {}
    for owner, helper, component, site in edges: successors.setdefault(owner, set()).add(helper)
    while pending:
        for helper in successors.get(pending.pop(), ()):
            if helper not in found: found.add(helper); pending.append(helper)
    return tuple(sorted(found))
