import ast
from pyobfuscator.cff.names import Namer, collect_names


def test_fresh_avoids_taken():
    n = Namer(seed=1, taken={"a", "b"})
    name = n.fresh("state")
    assert name not in {"a", "b"}
    assert name.startswith("_pyobf_")


def test_fresh_is_unique_each_call():
    n = Namer(seed=1, taken=set())
    names = {n.fresh("v") for _ in range(50)}
    assert len(names) == 50


def test_fresh_is_globally_unique_across_namers():
    """Cross-pass uniqueness by construction: the redesign (fix for the cross-pass name collision)
    draws fresh() names from a process-global monotonic counter, NOT a per-instance seeded RNG. So
    two Namers — even with the SAME seed — must NEVER hand out the same name (the old design did,
    relying only on each pass's `taken` set to avoid collisions; on the densely-named launcher that
    failed). Determinism of the final output is provided separately by cff.rename.finalize_names,
    not by fresh() being seed-reproducible — see test_determinism_comes_from_finalize_rename."""
    a = Namer(seed=7, taken=set())
    b = Namer(seed=7, taken=set())
    names_a = {a.fresh("x") for _ in range(5)}
    names_b = {b.fresh("x") for _ in range(5)}
    assert names_a.isdisjoint(names_b)


def test_determinism_comes_from_finalize_rename():
    """The counter advancing between builds must NOT change the finalized output: finalize_names
    maps the (run-varying) temp names to seed-derived hex by ast first-appearance order, so the
    same input tree + seed yields the same final names regardless of the counter's absolute value."""
    import ast as _ast
    from pyobfuscator.cff.rename import finalize_names

    def build_once():
        tree = _ast.parse("def f():\n    pass\n")
        fn = tree.body[0]
        nm = Namer(seed=7, taken=collect_names(fn))
        a = nm.fresh("x"); b = nm.fresh("y")
        # a tiny synthetic tree that uses both temp names
        body = _ast.parse(f"{a} = 1\n{b} = {a} + 1\n")
        finalize_names(body, 7)
        return _ast.unparse(body)

    first = build_once()
    # advance the global counter via an intervening, throwaway allocation
    Namer(seed=0).fresh("z")
    second = build_once()
    assert first == second
    assert "_pyobf_g" not in first  # temp form fully replaced by the hex final form


def test_collect_names_covers_names_args_and_funcname():
    tree = ast.parse("def f(a, b):\n    c = a + b\n    return c\n")
    fn = tree.body[0]
    got = collect_names(fn)
    assert {"f", "a", "b", "c"} <= got
