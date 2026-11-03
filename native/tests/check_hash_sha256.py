"""Compare actual Windows CNG output to the independent standard-library digest."""

import hashlib
import subprocess
import sys

result = subprocess.run([sys.argv[1]], capture_output=True, text=True, timeout=30)
if result.returncode: raise AssertionError(f"native SHA-256 boundary failed: {result.returncode}\n{result.stderr}")
lengths = [0, 1, 3, 55, 56, 63, 64, 65, 127, 128, 129, 1024, 4096, 65536]
lines = result.stdout.splitlines()
if len(lines) != len(lengths): raise AssertionError("native SHA-256 vector was skipped")
for length, line in zip(lengths, lines):
    actual_length, digest = line.split()
    payload = bytes((index * 131 + length * 17) & 255 for index in range(length))
    if int(actual_length) != length or digest != hashlib.sha256(payload).hexdigest():
        raise AssertionError(f"native SHA-256 differs for {length} bytes")
print("Windows CNG SHA-256: 14 reference vectors, four threads and invalid input/output/length boundaries verified")
