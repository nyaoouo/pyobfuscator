"""Independent canonical context-contribution values and bounded test diagnostics."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys


def context_word(private_words, routing_tag, point):
    fields = (routing_tag, *point, *private_words)
    material = b"pyobf.native.contribution.context.v1\0" + b"".join(value.to_bytes(4, "little") for value in fields)
    value = int.from_bytes(hashlib.sha256(material).digest()[:4], "little")
    return value or 1


def check(binary, runtime):
    environment = dict(os.environ)
    environment["PATH"] = str(runtime) + os.pathsep + environment.get("PATH", "")
    result = subprocess.run([binary], capture_output=True, text=True, env=environment, timeout=60)
    safe_output = "\n".join(line for line in result.stdout.splitlines() if not line.startswith("contribution-word "))
    if result.returncode: raise AssertionError(f"context contribution failed{result.returncode}:\n{safe_output}\n{result.stderr}")
    observed = [int(line.split()[1]) for line in result.stdout.splitlines() if line.startswith("contribution-word ")]
    point = (1, 2, 3, 4, 0x12345678)
    points = [point]
    for field in range(5):
        changed = list(point); changed[field] += 1; points.append(tuple(changed))
    expected = [context_word(range(1, 9), 0x11883377, point) for point in points]
    if observed != expected: raise AssertionError("actual context contribution differs from independent canonical SHA-256 reference")
    print(safe_output)
    print("six canonical context responses match independent Python reference")


if __name__ == "__main__":
    check(*map(Path, sys.argv[1:]))
