"""Scoped x86 COFF evidence for public-seeded opaque and junk transition expressions."""

from __future__ import annotations

from collections import Counter
import re


MASK = 0xffffffff


def component_seed(seed: int, function: str, domain: str) -> int:
    value = 2166136261 ^ seed
    for part in ("pyobf.cff.v1", function, domain):
        for byte in part.encode("utf-8"):
            value = ((value ^ byte) * 16777619) & MASK
        value = ((value ^ 0xff) * 16777619) & MASK
    return value


def check_transition_evidence(row: dict, code: str) -> None:
    components = {item["component"]: item for item in row.get("components", [])}
    opaque_count = sum(components.get(name, {}).get("applied", 0)
                       for name in ("opaque-choices", "bogus-clones", "bogus-synthesis"))
    if opaque_count:
        multiplies = re.findall(r"\bimull\s+([^\n]+)", code)
        variable = sum(not operands.lstrip().startswith("$") for operands in multiplies)
        if variable < opaque_count:
            raise SystemExit(f"linked DLL lost opaque transition products: {row['function']}")
    effective = row["effective_recipe"]
    actual = Counter(int(value, 16) for value in re.findall(r"\bimull\s+\$0x([0-9a-f]+)\b", code))
    decoy = components.get("decoy-transitions", {})
    if decoy.get("applied"):
        seed = next(item["seed"] for item in effective["components"] if item["component"] == "decoy-transitions")
        coefficient = ((seed ^ 0xa53c91eb) & ~0x10) | 0xa5a5a5a5
        if actual[coefficient] < decoy["applied"]:
            raise SystemExit(f"linked DLL lost decoy transition coefficients: {row['function']}")
        actual[coefficient] -= decoy["applied"]
    for name, rounds, label in (
            ("reachable-junk", effective["budgets"]["junk_rounds"], "reachable junk"),
            ("bogus-clones", 1, "bogus clone"),
            ("bogus-synthesis", effective["budgets"]["synthesis_rounds"], "bogus synthesis")):
        component = components.get(name, {})
        if not component.get("applied"):
            continue
        seed = next(item["seed"] for item in effective["components"] if item["component"] == name)
        expected = Counter()
        for site in component["sites"]:
            if site["status"] != "applied":
                continue
            origin = site["id"].rsplit(f":{name}:", 1)[0]
            salt = component_seed(seed, row["function"], origin)
            for index in range(rounds):
                key = (salt + index * 0x9e3779b9) & MASK
                expected[(key ^ 0x27d4eb2d) | 0x13579bd1] += site["applied_instances"]
        if not expected or any(actual[value] < count for value, count in expected.items()):
            raise SystemExit(f"linked DLL lost {label} coefficients: {row['function']}")
        actual.subtract(expected)
