from __future__ import annotations

import io
import contextlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Observation:
    result: object
    exc_type: str | None
    exc_msg: str | None
    stdout: str


def observe(callable_factory, args, kwargs) -> Observation:
    """Build a fresh callable via callable_factory(), call it, capture outcome."""
    fn = callable_factory()
    buf = io.StringIO()
    result = None
    exc_type = None
    exc_msg = None
    with contextlib.redirect_stdout(buf):
        try:
            result = fn(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001 - we are comparing behavior
            exc_type = type(e).__name__
            exc_msg = str(e)
    return Observation(result=result, exc_type=exc_type, exc_msg=exc_msg,
                       stdout=buf.getvalue())


def _original_factory(src: str, name: str):
    def factory():
        ns = {}
        exec(compile(src, "<orig>", "exec"), ns)
        return ns[name]
    return factory


def assert_func_equivalent(original_src, transformed_factory, func_name, batteries):
    orig_factory = _original_factory(original_src, func_name)
    for args, kwargs in batteries:
        o = observe(orig_factory, args, kwargs)
        t = observe(transformed_factory, args, kwargs)
        assert o == t, f"divergence on args={args} kwargs={kwargs}: {o} != {t}"
