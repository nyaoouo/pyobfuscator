"""Check reported per-site subsets without treating material as independent evidence."""

import re


def check_mixed_contribution_groups(proof, count, owner):
    source_mixed = proof.get("scheme_version") == 4
    sites, queries, helpers = proof.get("sites"), proof.get("query_count"), proof.get("helper_counts")
    if (not isinstance(sites, list) or len(sites) != count or type(queries) is not int or queries < count or
            proof.get("provider") != ("source-mixed-v1" if source_mixed else "site-mixed-v1") or
            proof.get("source_subset_contract_verified") is not True or
            proof.get("generated_owner_independence_verified") is not False or
            source_mixed and (proof.get("cross_provider_owner_binding_verified") is not False or
                proof.get("joint_helper_contract") not in (None, "source-mixed-context-v1") or
                proof.get("individual_sites_verified") is not False) or
            proof.get("operation_scope") != "per-site-invocation" or proof.get("measured_evidence_bits") != 256 or
            not isinstance(proof.get("private_input_sha256"), str) or
            re.fullmatch(r"[0-9a-f]{64}", proof["private_input_sha256"]) is None):
        raise SystemExit(f"mixed contribution evidence is incomplete: {owner}")
    identities, labels, points = {}, {}, set()
    counts = {"owned-context-v1": 0, "measured-scope-v1": 0}
    for index, site in enumerate(sites):
        if not isinstance(site, dict): raise SystemExit(f"mixed contribution site is invalid: {owner}")
        provider, subset, groups = site.get("provider"), site.get("sources"), site.get("groups")
        label = site.get("label")
        if ((provider != "source-mixed-v1" if source_mixed else provider not in counts) or
                type(site.get("provider_version")) is not int or site["provider_version"] != 1 or
                type(site.get("index")) is not int or site["index"] != index or
                type(label) is not int or not 0 < label < 2**32 or label in points or
                type(site.get("mixing_domain")) is not str or not site["mixing_domain"] or
                type(site.get("mixing_domain_tag")) is not int or not 0 < site["mixing_domain_tag"] < 2**32 or
                not isinstance(subset, list) or not subset or len(subset) > 256 or
                not source_mixed and provider == "measured-scope-v1" and len(subset) != 1 or not isinstance(groups, list)):
            raise SystemExit(f"mixed contribution site is invalid: {owner}")
        points.add(label)
        selected, selected_labels, covered = set(), set(), {}
        site_counts = {name: 0 for name in counts}
        for source in subset:
            if not isinstance(source, dict): raise SystemExit(f"mixed contribution source is invalid: {owner}")
            name, word, group = source.get("id"), source.get("word_label"), source.get("group")
            source_provider = source.get("provider")
            if (type(name) is not str or not name or type(word) is not int or not 0 < word < 2**32 or
                    type(group) is not str or not group or name in selected or word in selected_labels or
                    (source_provider not in counts if source_mixed else source_provider != provider) or
                    type(source.get("provider_version")) is not int or
                    source["provider_version"] != 1 or type(source.get("encoding")) is not int or
                    source["encoding"] != 1 or source.get("use") != "required-binding" or
                    source.get("class") != ("referenced-evidence" if source_provider == "measured-scope-v1" else "authenticated-material") or
                    source.get("sharing") != ("owner-independent" if source_provider == "measured-scope-v1" else "context-material") or
                    identities.get(name, (word, group, source_provider)) != (word, group, source_provider) or
                    labels.get(word, name) != name):
                raise SystemExit(f"mixed contribution source is invalid: {owner}")
            selected.add(name); selected_labels.add(word)
            identities[name] = (word, group, source_provider); labels[word] = name
            covered[group] = covered.get(group, 0) + 1
            site_counts[source_provider] += 1
        required = set()
        for group in groups:
            if not isinstance(group, dict): raise SystemExit(f"mixed contribution group is invalid: {owner}")
            name, minimum = group.get("id"), group.get("minimum")
            if (type(name) is not str or not name or type(minimum) is not int or minimum < 1 or
                    name in required or minimum > covered.get(name, 0) or group.get("independent_evidence") is not False):
                raise SystemExit(f"mixed contribution group is invalid: {owner}")
            required.add(name)
        if source_mixed:
            if site_counts["owned-context-v1"] < 1 or site_counts["measured-scope-v1"] != 1:
                raise SystemExit(f"source-mixed contribution site is incomplete: {owner}")
            for name, total in site_counts.items(): counts[name] += total
        else: counts[provider] += len(subset)
    if (counts["owned-context-v1"] == 0 or counts["measured-scope-v1"] == 0 or
            queries != sum(counts.values()) or type(helpers) is not dict or
            any(type(value) is not int for value in helpers.values()) or helpers != counts):
        raise SystemExit(f"mixed contribution helper evidence is incomplete: {owner}")
    return queries


def check_contribution_groups(proof, count, owner):
    if proof.get("scheme_version") in (3, 4):
        return check_mixed_contribution_groups(proof, count, owner)
    measured = proof.get("provider") == "measured-scope-v1"
    if proof.get("provider") not in ("owned-context-v1", "measured-scope-v1"):
        raise SystemExit(f"contribution source-group provider is unsupported: {owner}")
    sites, queries = proof.get("sites"), proof.get("query_count")
    invalid = (not isinstance(sites, list) or len(sites) != count or type(queries) is not int or
               queries < count or proof.get("source_subset_contract_verified") is not bool(count))
    identities, labels = {}, {}
    total = 0
    for index, site in enumerate(sites if isinstance(sites, list) else []):
        if not isinstance(site, dict): invalid = True; continue
        subset, groups = site.get("sources"), site.get("groups")
        invalid |= (type(site.get("index")) is not int or site["index"] != index or type(site.get("label")) is not int or not 0 < site["label"] < 2**32 or
            type(site.get("mixing_domain")) is not str or not site["mixing_domain"] or
            type(site.get("mixing_domain_tag")) is not int or not 0 < site["mixing_domain_tag"] < 2**32 or
            not isinstance(subset, list) or not subset or len(subset) > 256 or not isinstance(groups, list))
        selected, selected_labels, covered = set(), set(), {}
        if measured and (not isinstance(subset, list) or len(subset) != 1): invalid = True
        for source in subset if isinstance(subset, list) else []:
            if not isinstance(source, dict): invalid = True; continue
            name, label, group = source.get("id"), source.get("word_label"), source.get("group")
            if (type(name) is not str or not name or type(label) is not int or not 0 < label < 2**32 or
                    type(group) is not str or not group): invalid = True; continue
            invalid |= (name in selected or label in selected_labels or type(source.get("encoding")) is not int or source["encoding"] != 1 or
                source.get("class") != ("referenced-evidence" if measured else "authenticated-material") or
                source.get("sharing") != ("owner-independent" if measured else "context-material") or
                source.get("use") != "required-binding" or identities.get(name, (label, group)) != (label, group) or labels.get(label, name) != name)
            identities[name] = (label, group); labels[label] = name; selected.add(name); selected_labels.add(label)
            covered[group] = covered.get(group, 0) + 1
        total += len(subset) if isinstance(subset, list) else 0
        required = set()
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, dict): invalid = True; continue
            name, minimum = group.get("id"), group.get("minimum")
            if type(name) is not str or not name or type(minimum) is not int or minimum < 1: invalid = True; continue
            invalid |= name in required or minimum > covered.get(name, 0) or group.get("independent_evidence") is not False
            required.add(name)
    if invalid or total != queries:
        raise SystemExit(f"contribution source-group evidence is incomplete: {owner}")
    return queries
