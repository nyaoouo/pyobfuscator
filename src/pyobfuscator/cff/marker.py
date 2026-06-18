"""Marker decorators recognized by pyobfuscator. At runtime they are identity (no-ops), so
annotated source runs normally; the obfuscator strips them and acts on the annotation."""
from __future__ import annotations


def local_call(fn):
    """Mark a function so the obfuscator renames it to an opaque name (and inlines it at a single
    safe call site). Identity at runtime."""
    return fn
