"""Independent arbitrary-precision oracle for portable native deadline arithmetic."""
import argparse
from pathlib import Path
import random
import struct
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("probe", type=Path); parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    edges = (0, 1, 2, 3, 999, 1000, 10**7, 10**9, 2**32 - 1, 2**32, 2**63 - 1, 2**63, 2**64 - 1)
    vectors = [(ticks, frequency, ns) for ticks in edges for frequency in edges for ns in edges]
    randomizer = random.Random(0xD702B)
    vectors.extend(tuple(randomizer.getrandbits(64) for _ in range(3)) for _ in range(20000))
    for _ in range(2000):
        frequency = randomizer.getrandbits(64)
        maximum = min(2**64 - 1, (2**64 - 1) * 10**9 // max(frequency, 1))
        ns = randomizer.randrange(maximum + 1)
        boundary = ns * frequency // 10**9
        for ticks in (boundary - 1, boundary, boundary + 1):
            if 0 <= ticks < 2**64: vectors.append((ticks, frequency, ns))
    expected = bytes(ord('1') if frequency and ticks * 10**9 <= ns * frequency else ord('0')
        for ticks, frequency, ns in vectors)
    with tempfile.TemporaryDirectory(prefix="observer-time-", dir=args.build_dir) as temporary:
        path = Path(temporary) / "vectors.bin"
        path.write_bytes(b"".join(struct.pack("<QQQ", *values) for values in vectors))
        result = subprocess.run([str(args.probe), str(path)], capture_output=True, timeout=30)
        if result.returncode or result.stdout != expected:
            raise AssertionError(f"deadline arithmetic differs: exit{result.returncode}, {result.stderr[:1000]!r}")
    print(f"{len(vectors)} independent big-integer deadline vectors and native interval/policy controls pass")


if __name__ == "__main__": main()
