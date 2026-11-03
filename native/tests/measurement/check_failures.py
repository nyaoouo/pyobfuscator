"""Specific private capture error and fail-closed teardown process outcomes."""
import argparse
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("runtime_directory", type=Path)
    args = parser.parse_args()
    environment = dict(os.environ)
    environment["PATH"] = str(args.runtime_directory) + os.pathsep + environment.get("PATH", "")
    for extra, expected in (([], 0), (["close-failure"], 74)):
        result = subprocess.run([args.executable, *extra], capture_output=True, text=True, env=environment, timeout=15)
        if result.returncode != expected:
            raise AssertionError(f"capture error/teardown boundary differs: {extra}, code{result.returncode}\n{result.stdout}\n{result.stderr}")
    print("native capture failure/erasure/reentry and teardown-failure outcomes verified")


if __name__ == "__main__":
    main()
