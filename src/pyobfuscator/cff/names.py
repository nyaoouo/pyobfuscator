from __future__ import annotations

import ast
import random

# Cross-pass uniqueness by construction. Every pass builds its own `Namer(seed, taken)`, but they
# all share the SAME seed -> the old seeded RNG handed out the IDENTICAL sequence to each, so two
# passes could mint the same `_pyobf_<hex>` for different objects (a per-pass `taken` set only knew
# its own scope's names), leading to collisions.
#
# `fresh()` now draws from a process-global monotonic counter, so every name it ever hands out is
# unique across ALL passes by construction (collisions impossible). The temp names are then renamed
# to uniform `_pyobf_<hex>` by a single final seeded pass (cff/rename.finalize_names) run once per
# emitted tree. Determinism comes ENTIRELY from that final rename (ast tree-position order + seed)
# — NOT from the counter — so the counter grows naturally and is NEVER reset (its absolute values
# do not affect output).
_GEN_COUNTER = [0]
_GEN_ISSUED: set[str] = set()   # every name fresh() handed out, this process
# temp name -> {"role", "orig", "scope", "kind"}: out-of-band provenance for the opt-in sourcemap
# (cff/sourcemap.py). NEVER embedded in the emitted name (that would leak the role); recorded here
# only. Process-global+accumulating like _GEN_ISSUED; the sourcemap only reads the temps that appear
# in a given tree's finalize_names out_map, so accumulation across builds is harmless.
_GEN_META: dict[str, dict] = {}


def name_meta(temp: str) -> dict | None:
    """Provenance recorded for a temp name (`_pyobf_g<n>`) at fresh() time, or None. The sourcemap
    assembler joins this with finalize_names' temp->hex out_map to produce hex->{role,orig,...}."""
    return _GEN_META.get(temp)


class Namer:
    def __init__(self, seed=None, taken=()):
        # `seed` is retained for call-site compatibility; determinism lives in the final seeded
        # rename (cff/rename.finalize_names), not in name generation.
        self._rng = random.Random(seed)
        self._taken = set(taken)

    def fresh(self, hint: str = "v", *, orig: str | None = None,
              scope: str | None = None, kind: str = "var") -> str:
        # `hint` is the name's ROLE (state/push/junk/get/...). It is intentionally NOT embedded in
        # the name (that would leak the role); names are uniform `_pyobf_g<decimal>` (temp form,
        # distinct from the final `_pyobf_<hex>` whose hex never starts with 'g', and from the
        # double-underscore attest names). Instead the role — plus `orig` (original user identifier,
        # when renaming user code), `scope`, and `kind` if known at the call site — is recorded
        # out-of-band in _GEN_META for the opt-in sourcemap. The counter is global+monotonic so
        # every issued name is unique across every pass in this process; the `taken` guard skips
        # names already present in this scope (e.g. user code that happens to use the temp form).
        while True:
            name = f"_pyobf_g{_GEN_COUNTER[0]}"
            _GEN_COUNTER[0] += 1
            if name not in self._taken:
                self._taken.add(name)
                _GEN_ISSUED.add(name)
                _GEN_META[name] = {"role": hint, "orig": orig, "scope": scope, "kind": kind}
                return name


def collect_names(node: ast.AST) -> set[str]:
    """Every identifier that appears in `node` (names, args, def/class names)."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.arg):
            out.add(n.arg)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
        elif isinstance(n, ast.alias):
            out.add(n.asname or n.name.split(".")[0])
    return out
