"""Scoped x86 COFF evidence for typed state-dependent data transformations."""

from __future__ import annotations

import re


def check_data_evidence(row: dict, code: str) -> None:
    components = {item["component"]: item for item in row.get("components", [])}
    if components.get("integer-literals", {}).get("applied") and not re.search(r"\bimull\s+\$0x85ebca6b\b", code):
        raise SystemExit(f"linked DLL lost state-dependent literals: {row['function']}")
    comparison = components.get("comparison-constants", {})
    if not comparison.get("applied"):
        return
    types = comparison.get("applied_types", {})
    if sum(types.values()) != comparison["applied"]:
        raise SystemExit(f"comparison width evidence is incomplete: {row['function']}")
    lanes = sum(((int(name[1:]) + 31) // 32) * count for name, count in types.items())
    if len(re.findall(r"\bimull\s+\$0xd168aaad\b", code)) < lanes:
        raise SystemExit(f"linked DLL lost state-dependent comparison keys: {row['function']}")
