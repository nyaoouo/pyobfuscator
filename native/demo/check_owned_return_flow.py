"""Prove the production owned source return reaches the strict child CFF state."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def run(command, timeout=60):
    return subprocess.run([str(part) for part in command], capture_output=True,
                          text=True, timeout=timeout)


def require_success(result, label):
    if result.returncode:
        raise AssertionError(f"{label} failed ({result.returncode}): {result.stdout[-1000:]} {result.stderr[-1000:]}")


def detach_site_701_return(ir):
    start = ir.index("define internal noundef i32 @pyobf_demo_bound_compute(")
    end = ir.index("\n}\n", start)
    body = ir[start:end]
    matches = list(re.finditer(
        r"(?m)^  (%[\w.]+) = call i32 @pyobf_native_contribution_word_v1\([^\n]*, i32 701, [^\n]*\)[^\n]*$",
        body))
    if len(matches) != 1:
        raise AssertionError(f"expected one production site-701 query, found {len(matches)}")
    match = matches[0]
    # Keep the call and its query metadata. Detach every returned SSA use in this
    # function so a presence-only linked check still sees the original query.
    suffix = body[match.end():]
    suffix, uses = re.subn(rf"(?<![\w.]){re.escape(match.group(1))}(?![\w.])", "0", suffix)
    if uses < 1:
        raise AssertionError("site-701 query has no returned SSA use to detach")
    return ir[:start] + body[:match.end()] + suffix + ir[end:]


def main():
    parser = argparse.ArgumentParser()
    for name in ("probe", "image", "ir", "report", "private", "compiler", "objdump"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    reference = json.loads(args.private.read_text(encoding="utf-8"))
    if reference.get("provider") != "owned-context-v1" or reference.get("schema_version") != 1:
        raise AssertionError("test needs the actual schema1 owned production reference")
    words = reference["private_words"]
    if len(words) != 8 or any(type(word) is not int or not 0 <= word <= 0xffffffff for word in words):
        raise AssertionError("invalid actual private words")

    with tempfile.TemporaryDirectory(prefix="pyobf-owned-return-", dir=args.ir.parent) as directory:
        temporary = Path(directory)
        words_path = temporary / "words.bin"
        words_path.write_bytes(b"".join(word.to_bytes(4, "little") for word in words))

        def probe(image):
            return run((args.probe, image, "strict", "valid", words_path), timeout=10)

        original = probe(args.image)
        require_success(original, "original valid-source child")
        if not all(marker in original.stdout for marker in
                   ("legacy-admitted", "source-request", "payload-completed")):
            raise AssertionError(f"valid source did not complete admitted protected results: {original.stdout!r}")

        checker = Path(__file__).with_name("check_linked_cff.py")
        original_final = temporary / "original.final.json"
        original_check = run((sys.executable, checker, args.objdump, args.image,
                              args.report, "--output", original_final))
        require_success(original_check, "original linked CFF checker")
        if not original_final.is_file():
            raise AssertionError("original checker omitted final report")

        mutant_ir = temporary / "detached.ll"
        mutant_ir.write_text(detach_site_701_return(args.ir.read_text(encoding="utf-8")), encoding="utf-8")
        mutant_object = temporary / "detached.obj"
        mutant_image = temporary / "detached.dll"
        require_success(run((args.compiler, "-O0", "-fno-lto", "-c", "-x", "ir",
                             mutant_ir, "-o", mutant_object)), "mutant IR compilation")
        require_success(run((args.compiler, "-shared", mutant_object, "-o", mutant_image)),
                        "mutant child link")

        mutant_final = temporary / "mutant.final.json"
        rejected = run((sys.executable, checker, args.objdump, mutant_image,
                        args.report, "--output", mutant_final))
        if rejected.returncode == 0 or "lost owned query return flow" not in rejected.stderr + rejected.stdout:
            raise AssertionError(f"mutant final checker did not reject detached return: {rejected.stdout!r} {rejected.stderr!r}")
        if mutant_final.exists():
            raise AssertionError("rejected mutant received a final report")

        mutant = probe(mutant_image)
        if ("legacy-admitted" not in mutant.stdout or "source-request" not in mutant.stdout or
                "payload-completed" in mutant.stdout):
            raise AssertionError(f"mutant did not refuse normal result after admission/query: "
                                 f"code={mutant.returncode}, output={mutant.stdout!r}, error={mutant.stderr[-500:]!r}")
        print("schema1 owned production return flow: original accepted/completed; "
              "site-701 detached child rejected/no normal completion")


if __name__ == "__main__":
    main()
