"""Check the two-role POST lease/Scope source gate before mixed CFF."""

import argparse
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory


def run(command, *, success=True):
    result = subprocess.run([str(item) for item in command], capture_output=True, text=True)
    if (result.returncode == 0) != success:
        raise AssertionError(f"unexpected source gate result: {result.stderr[:700]}")
    if not success and "post child flow:" not in result.stderr:
        raise AssertionError(f"mutation failed outside the POST role gate: {result.stderr[:700]}")


def mutate(source, owner, argument):
    pattern = (rf"(?m)^([ \t]*[^\n]*\b(?:call|invoke)\b[^\n]*@{owner}\()"
               rf"(ptr [^,\n]+)" if argument == 0 else
               rf"(?m)^([ \t]*[^\n]*\b(?:call|invoke)\b[^\n]*@{owner}\(ptr [^,\n]+, )"
               rf"(ptr [^,\n]+)")
    changed, count = re.subn(pattern, r"\g<1>ptr null", source, count=1)
    if count != 1:
        raise AssertionError(f"could not detach {owner} argument {argument}")
    return changed


def main():
    parser = argparse.ArgumentParser()
    for name in ("opt", "plugin", "source", "output_directory"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="post-mixed-flow-", dir=args.output_directory) as temporary:
        root = Path(temporary)
        optimized = root / "optimized.ll"
        run((args.opt, "-passes=default<O2>", "-verify-each", "-S", args.source, "-o", optimized))
        for source in (args.source, optimized):
            command = (args.opt, "-load-pass-plugin=" + str(args.plugin),
                       "-passes=pyobf-native-post-child-source-verify", "-verify-each", "-disable-output")
            run((*command, source))
            raw = source.read_text(encoding="utf-8")
            for owner, argument in (("pyobf_demo_protection_wrapper", 0),
                                    ("pyobf_demo_protection_wrapper", 1),
                                    ("pyobf_demo_bound_compute", 0),
                                    ("pyobf_demo_bound_compute", 1)):
                bad = root / f"detached-{source.stem}-{owner}-{argument}.ll"
                bad.write_text(mutate(raw, owner, argument), encoding="utf-8")
                run((*command, bad), success=False)
    print("mixed POST source and O2 retain exact lease/Scope forwarding; four detachment cuts per profile refused")


if __name__ == "__main__":
    main()
