"""A require failure must terminate before the data-consumer sentinel."""

import argparse
from pathlib import Path
import subprocess


parser = argparse.ArgumentParser()
parser.add_argument("binary", type=Path)
args = parser.parse_args()
result = subprocess.run([str(args.binary), "fail"], capture_output=True, text=True, timeout=10)
if result.returncode == 0 or "DATA-CONSUMED" in result.stdout:
    raise SystemExit("archive failure reached the protected data consumer")
