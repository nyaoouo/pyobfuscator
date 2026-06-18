from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Diagnostic:
    lineno: int
    col_offset: int
    node_type: str
    message: str
    severity: Severity = Severity.ERROR

    def format(self) -> str:
        return f"[{self.severity.value}] line {self.lineno}: {self.message}"


class UnsupportedConstructError(Exception):
    def __init__(self, diagnostics):
        self.diagnostics = list(diagnostics)
        body = "\n".join(d.format() for d in self.diagnostics)
        super().__init__(
            f"{len(self.diagnostics)} unsupported construct(s):\n{body}"
        )
