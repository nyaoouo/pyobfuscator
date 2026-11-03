"""Production source protection and observed host linking for decoy acceptance."""

from collections import Counter
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import sys
import tempfile
import traceback

from cff_build import run
from session_build import complete_binary
from session_fold_reference import verify_coverage


@contextmanager
def fixture_directory(parent):
    directory = Path(tempfile.mkdtemp(prefix="decoy-runtime-", dir=parent))
    try:
        yield directory
    except BaseException:
        (directory / "failure.log").write_text(traceback.format_exc(), encoding="utf-8")
        print(f"Retained failed decoy runtime fixture: {directory}", file=sys.stderr)
        raise
    else:
        if directory.resolve().parent != parent.resolve() or not directory.name.startswith("decoy-runtime-"):
            raise AssertionError("decoy runtime cleanup escaped its owned directory")
        shutil.rmtree(directory)


def protect(args, directory, root, includes):
    units = []
    for index, source in enumerate(args.sources):
        unit = directory / f"source-{index}.ll"
        run([args.compiler, "-std=c++17", "-O0", "-S", "-emit-llvm", "-Xclang", "-disable-O0-optnone",
             "-DPYOBF_DEMO_ENABLE_DECOY=1", *includes, source, "-o", unit])
        units.append(unit)
    combined, requested = directory / "combined.ll", directory / "requested.ll"
    requests = directory / "requests.json"
    run([args.llvm_link, "-S", *units, "-o", combined])
    plugin = [args.opt, f"-load-pass-plugin={args.plugin}", f"-pyobf-cff-config={args.configuration}"]
    run([*plugin, "-passes=pyobf-native-cff-requests", f"-pyobf-cff-requests-output={requests}",
         "-verify-each", "-S", combined, "-o", requested])
    source = requested
    if args.profile == "O2":
        source = directory / "optimized.ll"
        run([args.opt, "-passes=default<O2>", "-verify-each", "-S", requested, "-o", source])
    transformed, report = directory / "protected.ll", directory / "coverage.json"
    run([*plugin, "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
         f"-pyobf-cff-report={report}", "-verify-each", "-S", source, "-o", transformed])
    rows = [row for row in json.loads(report.read_text())["functions"] if row["selected"]]
    expected = {"pyobf.native.cff": 2, "pyobf.native.sdk": 48,
                "pyobf.native.bootstrap": 28, "pyobf.native.bootstrap.eh": 3}
    if dict(Counter(row.get("marker") for row in rows)) != expected or any(
            row["status"] != "transformed" or not row["requested"] for row in rows):
        raise AssertionError("actual decoy session authored/request/CFF scope changed")
    verify_coverage(rows, decoy=True)
    return combined, transformed, report


def support(args, directory, root, includes):
    result = []
    sources = [("record", root / "backends/windows_user/release_record.cpp", []),
        ("hash", root / "backends/windows_user/operations/hash.cpp", ["-Dhash_sha256=hash_sha256_actual"]),
        ("crypto", root / "backends/windows_user/operations/crypto.cpp",
         ["-Ddecrypt_payload=decrypt_payload_actual", "-Ddecrypt_aead=decrypt_aead_actual"])]
    sources += [(name, root / "demo/decoy" / (name + ".cpp"), []) for name in
                ("runtime_backend", "runtime_crypto", "runtime_cases", "runtime_fault_smoke")]
    for name, source, defines in sources:
        obj = directory / (name + ".obj")
        run([args.compiler, "-std=c++17", "-O2", "-flto=thin" if args.ipo and name != "record" else "-fno-lto",
             *defines, *includes, "-c", source, "-o", obj])
        result.append(obj)
    return result


def link(args, directory, source, name, support_objects, includes, root, *, plain=False):
    obj, raw, binary = (directory / (name + suffix) for suffix in (".obj", ".raw.exe", ".exe"))
    run([args.compiler, "-O0", "-fno-lto", "-c", source, "-o", obj])
    run([args.compiler, "-std=c++17", "-O2", obj, *support_objects,
         *([root / "src/path_fold/marker.cpp"] if plain else []), *includes,
         *(["-flto=thin"] if args.ipo else []), "-lbcrypt", "-o", raw])
    complete_binary(raw, binary, args.record)
    return binary
