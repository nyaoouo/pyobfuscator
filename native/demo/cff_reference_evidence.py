"""Component-presence evidence for the supported x86 COFF reference-route profile."""

from __future__ import annotations

import re


def check_reference_evidence(row: dict, code: str, component_name: str = "reference-routes", coefficient: str = "165667b1") -> None:
    component = next((item for item in row.get("components", [])
                      if item["component"] == component_name), {})
    if not component.get("applied"):
        return
    roles = component.get("applied_types", {})
    if (set(roles) - {"call-target", "function-address"} or
            sum(roles.values()) != component["applied"]):
        raise SystemExit(f"reference role evidence is incomplete: {row['function']}")
    if len(re.findall(rf"\bimull\s+\$0x{re.escape(coefficient)}\b", code)) < component["applied"]:
        raise SystemExit(f"linked DLL lost state-dependent reference routes: {row['function']}")
    if len(re.findall(r"\b(?:callq?|jmpq?)\s+\*", code)) < roles.get("call-target", 0):
        raise SystemExit(f"linked DLL lost routed call targets: {row['function']}")
