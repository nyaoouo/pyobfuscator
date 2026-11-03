"""Function-scoped x86 fold presence, separate from per-site IR dataflow verification."""

import re


def check_path_fold_evidence(row: dict, code: str) -> None:
    component = next((item for item in row.get("components", []) if item["component"] == "path-fold"), {})
    if not component.get("applied"):
        return
    types = component.get("applied_types", {})
    initial, advance = types.get("initialize32x8", 0), types.get("advance32x8", 0)
    proof = row.get("path_fold", {})
    if (initial + advance != component["applied"] or proof.get("scheme_version") != 1 or
            proof.get("storage_bits") != 256 or not proof.get("ir_binding_contract_verified") or
            component.get("applied_roles", {}).get("decoy", 0)):
        raise SystemExit(f"path-fold IR binding/source evidence is incomplete: {row['function']}")
    floor = max(1, row.get("site_totals", {}).get("transition_sites", 2)) + initial * 9 + advance * 2
    for coefficient in ("7feb352d", "846ca68b"):
        if len(re.findall(rf"\bimull\s+\$0x{coefficient}\b", code)) < floor:
            raise SystemExit(f"linked image lost path-fold arithmetic presence: {row['function']}")
    if not component.get("unsupported") and re.search(r"\bcallq?\s+[^\n]*pyobf_native_path_fold_(?:init|step)_v1", code):
        raise SystemExit(f"linked selected fold sites still call the ordinary reference: {row['function']}")
