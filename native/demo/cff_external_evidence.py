"""Scoped final-code evidence for private typed external-call adapters."""

from cff_frame_evidence import check_frame_evidence


def check_external_evidence(report: dict, row: dict, code: str) -> None:
    check_frame_evidence(report, row, code, "external-calls")
