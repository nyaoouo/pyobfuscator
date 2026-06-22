"""Entry point. Built with publish_runtime: its launcher installs the shared decrypt runtime
(decrypt + attestation oracle) into builtins before running, so the protected satellite modules
decrypt through it. Run: ``python dist/main.py <license-key> <payload>``."""
import sys

from app.logic import run


def main():
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    payload = sys.argv[2] if len(sys.argv) > 2 else ""
    print(run(key, payload))


if __name__ == "__main__":
    main()
