"""CPU-bound benchmark workload: integer arithmetic, branches, nested loops.

Self-timing so the obfuscated artifact reports its own hot-loop wall time: prints
``ELAPSED=<seconds>`` and ``CHECKSUM=<int>``. The checksum mixes every iteration's result, so
it changes if a build silently diverges (the harness compares it against the baseline). Runs
standalone as ``python cpu_workload.py``.

Kept to gate-supported constructs only (def / for / while / if-elif-else / aug-assign /
arithmetic / comparisons) so every obfuscation flag can build it.
"""
import time

MASK = 0xFFFFFFFF


def _kernel(n, seed):
    x = (1234567 + seed * 2654435761) & 0x7FFFFFFF
    acc = 0
    for i in range(n):
        x = (1103515245 * x + 12345) & 0x7FFFFFFF
        if x % 3 == 0:
            acc = (acc + x % 97) & MASK
        elif x % 5 == 0:
            acc = (acc - x % 13) & MASK
        else:
            acc ^= (x >> 7)
        if x % 100 == 47:          # eligible for hide_compares (== CONST, |CONST| > 1)
            acc = (acc + 1) & MASK
        j = 0
        while j < 4:
            acc = (acc + j * x) & MASK
            j += 1
    return acc


def bench_run():
    iters = 600
    size = 240
    t0 = time.perf_counter()
    total = 0
    for k in range(iters):
        total = (total * 1000003 + _kernel(size, k)) & MASK
    dt = time.perf_counter() - t0
    print("ELAPSED=%.6f" % dt)
    print("CHECKSUM=%d" % total)


if __name__ == "__main__":
    bench_run()
