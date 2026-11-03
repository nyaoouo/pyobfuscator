"""Scoped final-code evidence for the separate imported-address route domain."""

from cff_reference_evidence import check_reference_evidence


def check_import_evidence(row: dict, code: str) -> None:
    check_reference_evidence(row, code, "import-routes", "d3a2646d")
