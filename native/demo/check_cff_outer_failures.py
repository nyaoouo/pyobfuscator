"""Reject an executable same-source unprotected outer and forced whole-EH coverage."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

from check_cff_transition_depth import run
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from pe_release_record import finalize_image
import measured_artifacts


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "objdump", "checker", "combined", "report",
                 "configuration", "smoke", "build_dir", "record"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--backend-source", type=Path, action="append", default=[])
    parser.add_argument("--library", action="append", default=[])
    parser.add_argument("--blocked", action="store_true")
    parser.add_argument("--decoy", action="store_true")
    measured_artifacts.arguments(parser)
    args = parser.parse_args()
    name = args.combined.name.removesuffix(".combined.ll")
    measured_artifacts.bind(args, parser, [name])
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        image, absent = directory / "plain-outer.dll", directory / "rejected.json"
        raw = directory / "plain-outer.raw.dll"
        root = Path(__file__).resolve().parents[1]
        source, parent_object = args.combined, None
        if measured_artifacts.function_sections(args, name):
            parent_object = directory / "plain.obj"
            run([str(args.compiler), "-O0", "-fno-lto", "-ffunction-sections", "-c", str(source), "-o", str(parent_object)])
            source = parent_object
        run([str(args.compiler), "-std=c++17", "-O0", "-fno-lto", "-shared", str(source),
             *map(str, args.backend_source), str(root / "src/path_fold/marker.cpp"),
             str(measured_artifacts.record_source(args, root)), *map(str, measured_artifacts.objects(args, name)),
             "-I", str(root / "include"), "-I", str(root / "src"),
             *(f"-l{name}" for name in args.library), "-o", str(raw)])
        ownership = measured_artifacts.emission_ownership(args, name, parent_object, args.combined, None, run)
        image.write_bytes(measured_artifacts.complete(args, raw.read_bytes(), name, parent_object=parent_object,
            parent_ownership=ownership))
        mode = (["denied" if args.blocked else "allowed"] if args.decoy else ["triggered"] if args.blocked else
            ["post"] if args.post_inputs else [])
        run([str(args.smoke), str(image), *mode])
        result = run([sys.executable, str(args.checker), str(args.objdump), str(image),
                      str(args.report), "--output", str(absent),
                      *map(str, measured_artifacts.reader_arguments(args, name))], succeeds=False)
        rejected_code = "owner reader final evidence failed" if name in args.reader_inputs else "lost the expected relative-tree shape"
        if absent.exists() or rejected_code not in result.stderr:
            raise AssertionError("executable same-source outer passed without CFF or failed outside the shape gate")

        configuration = json.loads(args.configuration.read_text())
        hybrid = [row["function"] for row in json.loads(args.report.read_text())["functions"]
                  if row.get("marker") == "pyobf.native.bootstrap.eh"]
        if len(hybrid) != (3 if args.decoy else 2): raise AssertionError("outer EH negative lost its authored functions")
        for name in hybrid:
            configuration.setdefault("functions", {}).setdefault(name, {})["coverage"] = "whole"
        config, report, output = (directory / name for name in ("wrong.json", "wrong-report.json", "wrong.ll"))
        config.write_text(json.dumps(configuration), encoding="utf-8")
        run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
             f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", "-verify-each",
             "-S", str(args.combined), "-o", str(output)], succeeds=False)
        rows = {row["function"]: row for row in json.loads(report.read_text())["functions"]}
        if output.exists() or any(rows[name]["status"] != "unsupported" or
                "supports branches" not in rows[name]["reason"] for name in hybrid):
            raise AssertionError("outer whole-scope request silently became hybrid coverage")


if __name__ == "__main__":
    main()
