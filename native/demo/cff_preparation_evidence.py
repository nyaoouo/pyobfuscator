"""Function-scoped final-code evidence for state-dependent owned frame addressing."""

import re


def check_preparation_evidence(row: dict, code: str) -> None:
    component = next((item for item in row.get("components", []) if item["component"] == "call-preparation"), {})
    if not component.get("applied"):
        return
    metrics = component.get("preparation", {})
    addresses = metrics.get("field_addresses", 0)
    if (not addresses or metrics.get("logical_sites") != component["applied"] or
            metrics.get("state_steps") != addresses + component["applied"] or
            len(re.findall(r"\bimull\s+\$0x27d4eb2d\b", code)) < addresses):
        raise SystemExit(f"linked DLL lost state-dependent call preparation: {row['function']}")
