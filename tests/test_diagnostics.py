import pytest
from pyobfuscator.cff.diagnostics import Severity, Diagnostic, UnsupportedConstructError


def test_diagnostic_format():
    d = Diagnostic(lineno=42, col_offset=4, node_type="Yield", message="`Yield` is not supported")
    assert d.severity is Severity.ERROR
    assert d.format() == "[error] line 42: `Yield` is not supported"


def test_error_carries_all_diagnostics():
    diags = [
        Diagnostic(1, 0, "Yield", "`Yield` is not supported"),
        Diagnostic(2, 0, "AsyncFunctionDef", "`AsyncFunctionDef` is not supported"),
    ]
    err = UnsupportedConstructError(diags)
    assert err.diagnostics == diags
    text = str(err)
    assert "2 unsupported construct(s)" in text
    assert "line 1" in text and "line 2" in text


def test_warning_severity_formats():
    d = Diagnostic(3, 0, "Call", "name may be imported elsewhere", severity=Severity.WARNING)
    assert d.format() == "[warning] line 3: name may be imported elsewhere"
