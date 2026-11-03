"""Scoped x86 COFF evidence for actual-state local-object address routes."""

import re


def check_local_evidence(row: dict, code: str) -> None:
    component = next((item for item in row.get("components", []) if item["component"] == "indexed-locals"), {})
    if not component.get("applied"):
        return
    metrics = component.get("preparation", {})
    routes = metrics.get("address_routes", 0)
    if (metrics.get("objects") != component["applied"] or routes < component["applied"] or
            sum(component.get("applied_types", {}).values()) != component["applied"] or
            len(re.findall(r"\bimull\s+\$0x9e6c63d1\b", code)) < routes):
        raise SystemExit(f"linked DLL lost indexed local address routes: {row['function']}")
