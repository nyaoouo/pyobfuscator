"""String/bytes-bound benchmark workload: building, hashing, slicing, joining.

Self-timing like cpu_workload (prints ``ELAPSED=`` and ``CHECKSUM=``; the checksum mixes every
iteration so it guards against a silently diverging build). Exercises the data/string-oriented
flags (obf_strings, const_archive, hide_compares, name_vault). Runs standalone as
``python str_workload.py``. Gate-supported constructs only.
"""
import time

MASK = 0xFFFFFFFF


def _kernel(n, seed):
    parts = []
    h = seed & MASK
    for i in range(n):
        s = "abc" + str(i) + "_xyz"
        for c in s:
            h = (h * 131 + ord(c)) & MASK
        if i % 7 == 0:
            parts.append(s[::-1])
    joined = "|".join(parts)
    return h, len(joined)


def bench_run():
    iters = 350
    size = 160
    t0 = time.perf_counter()
    th = 0
    for k in range(iters):
        h, l = _kernel(size, k)
        th = (th * 131 + h + l) & MASK
    dt = time.perf_counter() - t0
    print("ELAPSED=%.6f" % dt)
    print("CHECKSUM=%d" % th)


if __name__ == "__main__":
    bench_run()
