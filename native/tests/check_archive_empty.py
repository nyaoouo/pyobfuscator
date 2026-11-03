"""Verify no-pool compiler handoffs, strict original obligations and empty-phase rejection."""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from archive_empty_pipeline import check_cmake
from archive_plan_cases import HEADER

EMPTY = HEADER + '''
define dllexport i32 @identity(i32 %value) nofree nosync memory(none) {
entry:
  ret i32 %value
}
define dllexport void @nothing() { ret void }
'''
FOLDED = EMPTY + '''
@data = private constant i32 77
define dllexport i32 @folded() {
entry:
  %value = load i32, ptr @data
  ret i32 %value
}
'''


def run(command, *, succeeds=True):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=120)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f"empty archive command differs: {command}\n{result.stdout}\n{result.stderr}")
    return result


def probe(image: Path, runtime: Path) -> None:
    with os.add_dll_directory(str(runtime)):
        module = ctypes.CDLL(str(image))
    module.identity.argtypes, module.identity.restype = [ctypes.c_int], ctypes.c_int
    module.nothing.argtypes, module.nothing.restype = [], None
    for value in (-2147483648, -91, 0, 77, 2147483647):
        if module.identity(value) != value: raise AssertionError("empty protected identity changed its argument")
    module.nothing()
    if hasattr(module, "folded") and module.folded() != 77:
        raise AssertionError("optimized-away archive input changed its scalar result")


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "--probe":
        probe(Path(sys.argv[2]), Path(sys.argv[3]))
        return
    parser = argparse.ArgumentParser()
    for name in ("cmake", "ninja", "compiler", "opt", "plugin", "llvm_link", "objdump", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.environ["PATH"] = str(args.compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    with tempfile.TemporaryDirectory(prefix="empty archive ", dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, config, requests, requested, plan, pending, prepared, final, report = [directory / name for name in
            ("source.ll", "recipe.json", "requests.json", "requested.ll", "plan.json", "pending.ll",
             "prepared.ll", "protected.ll", "coverage.json")]
        package, generated, bindings = [directory / name for name in ("pool.bin", "pool.cpp", "bindings.json")]
        base = [args.opt, f"-load-pass-plugin={args.plugin}", "-verify-each"]
        settings = {"schema_version": 1, "functions": {name: {"components": {
            "constant-archive": "optional", "integer-literals": "optional"}} for name in ("identity", "nothing")}}
        source.write_text(EMPTY, encoding="utf-8")
        config.write_text(json.dumps(settings), encoding="utf-8")
        selection = [f"-pyobf-cff-config={config}"]
        run([*base, "-passes=pyobf-native-cff-requests", *selection,
             f"-pyobf-cff-requests-output={requests}", "-S", source, "-o", requested])
        run([*base, "-passes=pyobf-native-archive-plan", *selection,
             f"-pyobf-archive-plan-output={plan}", "-S", requested, "-o", pending])
        text = pending.read_text()
        if (json.loads(plan.read_bytes())["records"] or "memory(none)" not in text or
                "@__pyobf_archive_" in text or "pyobf.archive.key-" in text):
            raise AssertionError("empty planning generated work or invalidated original purity")
        for passes, extra in (("pyobf-native-cff", []),
                ("pyobf-native-cff-requests", [f"-pyobf-cff-requests-output={directory / 'reentry.json'}"]),
                ("pyobf-native-archive-plan", [f"-pyobf-archive-plan-output={directory / 'reentry.json'}"])):
            result = run([*base, f"-passes={passes}", *selection, *extra, "-disable-output", pending], succeeds=False)
            if "pending wrapper and state-key" not in result.stderr:
                raise AssertionError("empty pending plan escaped its unfinished-stage boundary")
        pack = [sys.executable, root / "tools" / "pack_archive.py", plan, package, generated, bindings]
        run(pack, succeeds=False)
        if any(path.exists() for path in (package, generated, bindings)):
            raise AssertionError("default packer accepted or partially emitted an empty runtime pool")
        run([*pack, "--allow-empty-plan"])
        original = json.loads(bindings.read_bytes())
        if (package.read_bytes() or original["records"] or original["archive_id"] != "00" * 16 or
                original["package_sha256"] != hashlib.sha256(b"").hexdigest() or "package_bytes" in generated.read_text()):
            raise AssertionError("empty handoff contains a pool, record, cache or secret")

        def materialize(input_ir=pending, manifest=bindings, *, succeeds=True):
            return run([*base, "-passes=pyobf-native-archive-materialize", f"-pyobf-archive-bindings={manifest}",
                "-S", input_ir, "-o", prepared], succeeds=succeeds)

        altered, bad = directory / "altered.ll", directory / "bad.json"
        for field, value in (("plan_sha256", "00" * 32), ("package_sha256", "00" * 32), ("archive_id", "11" * 16)):
            document = dict(original, **{field: value})
            bad.write_text(json.dumps(document), encoding="utf-8")
            materialize(manifest=bad, succeeds=False)
        mutations = [
            text + '\n@__pyobf_archive_stray = private global i8 0\n',
            text.replace('ret i32 %value', 'ret i32 %value, !pyobf.archive.key-material !999') + '\n!999 = !{}\n',
            text.replace('!pyobf.archive.sources = !{}', '!pyobf.archive.sources = !{!999}') + '\n!999 = !{}\n',
            text.replace('@identity(i32 %value)', '@identity(i32 %value) "pyobf.archive.planned"'),
            text + '\n!pyobf.archive.unknown = !{!999}\n!999 = !{}\n',
        ]
        for mutation in mutations:
            altered.write_text(mutation, encoding="utf-8")
            failure = materialize(input_ir=altered, succeeds=False)
            if "native archive binding: empty plan" not in failure.stderr:
                raise AssertionError(f"malformed empty inventory failed outside its intended validation: {failure.stderr}")
        materialize()
        saved = prepared.read_text()
        for passes, extra in (("pyobf-native-cff-requests", [f"-pyobf-cff-requests-output={bad}"]),
                              ("pyobf-native-archive-plan", [f"-pyobf-archive-plan-output={bad}"])):
            run([*base, f"-passes={passes}", *selection, *extra, "-disable-output", prepared], succeeds=False)
        cff = [*base, "-passes=pyobf-native-cff", *selection,
               f"-pyobf-cff-requests-input={requests}", f"-pyobf-cff-report={report}"]
        altered.write_text(re.sub(r'^!pyobf.archive.prepared = .*\n', '', saved, flags=re.M), encoding="utf-8")
        run([*cff, "-S", altered, "-o", final], succeeds=False)
        malformed = re.sub(r'^!pyobf.archive.empty = .*$', '!pyobf.archive.empty = !{!999}', saved, flags=re.M)
        altered.write_text(malformed + '\n!999 = !{i32 1}\n', encoding="utf-8")
        run([*cff, "-S", altered, "-o", final], succeeds=False)
        run([*cff, "-S", prepared, "-o", final])
        if "!pyobf.archive." in final.read_text(): raise AssertionError("empty build-only flags survived final CFF")
        rows = json.loads(report.read_bytes())["functions"]
        for row in rows:
            if row["selected"]:
                component = next(item for item in row["components"] if item["component"] == "constant-archive")
                if row["status"] != "transformed" or component["eligible"] or component["applied"]:
                    raise AssertionError("empty source received phantom archive coverage")
        image = directory / "empty.dll"
        run([args.compiler, "-O0", "-fno-lto", "-shared", final, "-o", image])
        run([sys.executable, __file__, "--probe", image, args.compiler.parent])
        run([sys.executable, root / "demo" / "check_linked_cff.py", args.objdump, image, report])
        strict = copy.deepcopy(settings)
        strict["functions"]["identity"]["components"]["constant-archive"] = "required"
        config.write_text(json.dumps(strict), encoding="utf-8")
        run([*cff, "-S", prepared, "-o", final], succeeds=False)
        failure = next(row for row in json.loads(report.read_bytes())["functions"] if row["function"] == "identity")
        if failure.get("reason") != "constant-archive has zero eligible required sites":
            raise AssertionError(f"required empty archive failed outside its coverage boundary: {failure}")
        source.write_text(FOLDED, encoding="utf-8")
        settings["functions"]["folded"] = copy.deepcopy(settings["functions"]["identity"])
        config.write_text(json.dumps(settings), encoding="utf-8")
        nonempty, nonempty_plan = directory / "nonempty.ll", directory / "nonempty.json"
        run([*base, "-passes=pyobf-native-archive-plan", *selection,
             f"-pyobf-archive-plan-output={nonempty_plan}", "-S", source, "-o", nonempty])
        bad.write_text(json.dumps(dict(original, plan_sha256=hashlib.sha256(nonempty_plan.read_bytes()).hexdigest())),
                       encoding="utf-8")
        materialize(input_ir=nonempty, manifest=bad, succeeds=False)
        erased = re.sub(r'^!pyobf.archive.records = .*$', '!pyobf.archive.records = !{}', nonempty.read_text(), flags=re.M)
        altered.write_text(erased, encoding="utf-8")
        materialize(input_ir=altered, manifest=bad, succeeds=False)
        check_cmake(args, directory, source, config, run, Path(__file__), EMPTY, FOLDED, settings)


if __name__ == "__main__":
    main()
