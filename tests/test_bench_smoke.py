"""Smoke test for the performance benchmark harness (bench/benchmark.py).

Guards the harness against bit-rot WITHOUT asserting any performance threshold — perf numbers are
machine-dependent and must never gate the suite. Only the build/size/render code paths are
exercised; no subprocess timing is run here (that belongs to a manual benchmark run).
"""
import os
import sys

BENCH_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench")
if BENCH_DIR not in sys.path:
    sys.path.insert(0, BENCH_DIR)

import benchmark  # noqa: E402


def test_build_matrix_shapes():
    rows = benchmark.build_matrix(quick=True)
    assert rows, "matrix is empty"
    for section, label, output, opts in rows:        # each row is a 4-tuple
        assert section and label
        assert output in ("text", "pyc")
        assert isinstance(opts, dict)


def test_build_artifact_returns_text_and_time():
    src = "def f(x):\n    y = 0\n    for i in range(x):\n        y += i\n    return y\n"
    artifact, build_s = benchmark.build_artifact(src, "text", {}, reps=1)
    assert isinstance(artifact, str) and artifact
    assert build_s >= 0.0


def test_render_markdown_produces_tables():
    results = {
        "meta": {"python": "3.x", "platform": "test", "processor": "test", "seed": 1,
                 "build_reps": 1, "run_reps": 1, "boot_s": 0.0},
        "workloads": [{
            "name": "demo", "raw_runtime_s": 0.01, "raw_checksum": 0, "raw_size_b": 10,
            "rows": [{"section": "CFF", "label": "baseline", "output": "text", "build_ms": 1.0,
                      "size_b": 100, "runtime_x": 1.0, "startup_ms": 1.0, "status": "ok"}],
        }],
    }
    md = benchmark.render_markdown(results)
    assert "measured performance" in md
    assert "Workload: `demo`" in md
    assert "baseline" in md
