"""Source target closure and explicitly weaker ordinary marker semantics."""
import os
from pathlib import Path
import subprocess
import sys

binary, runtime = map(Path, sys.argv[1:])
environment = dict(os.environ)
environment["PATH"] = str(runtime) + os.pathsep + environment.get("PATH", "")
for mode in ("normal", "wrong", "provider", "closed", "unbound", "empty", "foreign"):
    result = subprocess.run([binary, mode], env=environment, capture_output=True, text=True, timeout=15)
    if result.returncode or "gate-normal-completed" not in result.stdout:
        raise AssertionError(f"source reference closure/strict scalar failed {mode}: {result.returncode}\n{result.stdout}\n{result.stderr}")
failed = subprocess.run([binary, "fail-scalar"], env=environment, capture_output=True, text=True, timeout=15)
if (failed.returncode & 0xffffffff) != 0xe04f0702 or "gate-enter" in failed.stdout:
    raise AssertionError(f"generated owned helper did not fail before the protected path: {failed.returncode}\n{failed.stdout}\n{failed.stderr}")
print("source gate/provider/reference targets: strict scalar status sanitization, generated-helper failure and seven ordinary marker modes verified")
