"""Scoped final-code evidence for typed frame invokers and their owning callers."""

from __future__ import annotations

import re


def check_frame_evidence(report: dict, row: dict, code: str, component_name: str = "call-frames") -> None:
    if row.get("generation_component") == component_name:
        if not re.search(r"\b(?:callq?|jmpq?)\s+\*", code):
            raise SystemExit(f"linked DLL lost typed frame invoker: {row['function']}")
        return
    component = next((item for item in row.get("components", []) if item["component"] == component_name), {})
    if not component.get("applied"):
        return
    helpers = [item for item in report["functions"] if item.get("generation_component") == component_name
               and item.get("generated_owner") == row["function"]]
    roles = component.get("applied_types", {})
    if (len(helpers) != component["applied"] or set(roles) - {"void", "value"} or
            sum(roles.values()) != component["applied"] or any(not item.get("selected") or
            item["status"] != "transformed" or item.get("requested") for item in helpers)):
        raise SystemExit(f"call frame helper inventory is incomplete: {row['function']}")
    references = next((item for item in row["components"] if item["component"] == "reference-routes"), {})
    for helper in helpers:
        name = re.escape(helper["function"].lower())
        pattern = rf"<{name}>" if references.get("applied") else rf"\b(?:callq?|jmpq?)\s+[^\n]*<{name}>"
        if not re.search(pattern, code):
            raise SystemExit(f"linked DLL lost an owned call frame route: {row['function']}")
