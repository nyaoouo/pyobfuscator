"""Pin POST child role provenance and validation gates after source O2."""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile


ENTRY = re.compile(r"(?ms)^define [^\n]*@pyobf_demo_post_payload\([^\n]*\{\n(.*?)^\}")


def verify(opt, plugin, source, pass_name, *, refused=False):
    result = subprocess.run(
        [opt, "-load-pass-plugin", plugin, f"-passes={pass_name}", "-disable-output", source],
        capture_output=True, text=True, timeout=30,
    )
    if refused:
        if result.returncode == 0 or "post child flow:" not in result.stderr:
            raise AssertionError(f"POST child mutant was not specifically refused: {result.stderr[-600:]}")
    elif result.returncode:
        raise AssertionError(f"valid POST child failed source/transform verification: {result.stderr[-600:]}")


def mutate_entry(source, old, new, count=1):
    match = ENTRY.search(source)
    if match is None or match.group(1).count(old) != count:
        raise AssertionError(f"O2 POST child entry did not have {count} pinned {old!r} source site(s)")
    return source[:match.start(1)] + match.group(1).replace(old, new, 1) + source[match.end(1):]


def main():
    parser = argparse.ArgumentParser()
    for name in ("opt", "plugin", "source_ir", "transformed_ir", "scratch"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    source = args.source_ir.read_text(encoding="utf-8")
    entry = ENTRY.search(source)
    if entry is None or "getelementptr inbounds nuw i8" not in entry.group(1):
        raise AssertionError("fixture did not retain the optimized byte-offset role form")
    verify(args.opt, args.plugin, args.source_ir, "pyobf-native-post-child-source-verify")
    verify(args.opt, args.plugin, args.transformed_ir, "pyobf-native-post-child-verify")
    cases = (
        ("foreign post field", "ptr %0, i64 48", "ptr %0, i64 16", 1),
        ("observer role collapse", "i64 88", "i64 184", 1),
        ("material role swap", "i64 96", "i64 192", 1),
        ("validation gate inversion", "icmp eq i32", "icmp ne i32", 2),
    )
    with tempfile.TemporaryDirectory(prefix="post-child-o2-", dir=args.scratch) as temporary:
        for label, old, new, count in cases:
            candidate = Path(temporary) / (label.replace(" ", "-") + ".ll")
            candidate.write_text(mutate_entry(source, old, new, count), encoding="utf-8")
            verify(args.opt, args.plugin, candidate, "pyobf-native-post-child-source-verify", refused=True)
    print("optimized POST child source/transform and four independent provenance/gate refusals verified")


if __name__ == "__main__":
    main()
