"""Actual archived payload wrappers, shared source ownership and closed native reads."""
from pathlib import Path
import ctypes
import json
import sys

from check_capture import ROOT, check_native
from cff_build import run, verify_image
from function_inventory import Ownership, create, helpers
from generated_function_subject import generated_function_subject
from generated_ownership import graph
from pe_layout import parse_image


def check_archive(args, directory, ir, report_path, *, shared_required=False):
    report = report_path.read_bytes()
    rows, edges = graph(report)
    archive = [edge for edge in edges if edge[2] == "constant-archive"]
    if not archive: raise AssertionError("production archive fixture lost actual wrapper acquisitions")
    changed = json.loads(report)
    entry = next(row for row in changed["functions"] if row.get("archive_sources", {}).get("helpers"))
    entry["archive_sources"]["helpers"][0]["source_id"] += ":foreign"
    try: graph(json.dumps(changed).encode())
    except ValueError as error:
        if "original source" not in str(error): raise
    else: raise AssertionError("archive helper source detached from its actual acquisition")
    shared = {}
    for owner, helper, component, site in archive: shared.setdefault(helper, set()).add(owner)
    repeated = [owners for owners in shared.values() if len(owners) > 1]
    if shared_required and not repeated: raise AssertionError("archive fixture lost its genuinely shared wrapper")
    owners = sorted(repeated[0] if repeated else {edge[0] for edge in archive})[:2]
    native, binary = directory / "archive.obj", directory / "archive.dll"
    run([args.compiler, "-O0", "-fno-lto", "-ffunction-sections", "-c", ir, "-o", native])
    run([args.compiler, "-shared", "-fno-lto", native, ROOT / "tests/measurement/generated_support.cpp", "-lbcrypt", "-o", binary])
    verify_image([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump], binary, report_path, directory / "archive.final.json")
    obj, data = native.read_bytes(), binary.read_bytes()
    proof = Ownership(create(obj, ir.read_bytes(), report), report)
    for index, name in enumerate(owners):
        targets = helpers(obj, proof, name)
        subject = generated_function_subject(obj, data, parse_image(data), 0x620 + index, name, proof)
        if not targets or len(subject.ranges) < 2: raise AssertionError("archive subject omitted its actual generated wrapper")
        check_native(args.probe, args.runtime_directory, directory, binary, data, parse_image(data), subject)
    if shared_required:
        library = ctypes.WinDLL(str(binary.resolve()))
        try:
            for name in ("archive_compute", "archive_pointer"):
                function = getattr(library, name); function.argtypes = [ctypes.c_uint]; function.restype = ctypes.c_uint
                for value in (0, 1, 7, 31, 100, 0xffffffff):
                    item = (3, 5, 11, 17)[value & 3]
                    expected = (item + value) & 0xffffffff if name == "archive_compute" else item ^ value
                    if function(value) != expected: raise AssertionError("shared archive helper changed actual source results")
        finally:
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]; kernel.FreeLibrary.restype = ctypes.c_int
            if not kernel.FreeLibrary(library._handle): raise OSError(ctypes.get_last_error(), "release shared archive")
    print(f"actual archive: {len(archive)} typed acquisitions in {len(owners)} independently captured source subjects; shared wrapper={bool(repeated)}")


def check_shared(args, directory):
    sys.path.insert(0, str(ROOT / "demo"))
    from archive_measure_build import build_variant
    work = directory / "shared"
    build_variant(args, ROOT, ROOT / "tests/measurement/generated_archive.ll", work, "archive", "none")
    check_archive(args, work, work / "protected.ll", work / "coverage.json", shared_required=True)
    if args.previous_plugin:
        previous = work / "previous.ll"
        run([args.opt, f"-load-pass-plugin={args.previous_plugin}", "-passes=pyobf-native-cff",
            f"-pyobf-cff-config={work / 'recipe.json'}", "-pyobf-cff-seed=731",
            f"-pyobf-cff-requests-input={work / 'merged.requests.json'}", "-verify-each", "-S", work / "prepared.ll", "-o", previous])
        if previous.read_bytes() != (work / "protected.ll").read_bytes():
            raise AssertionError("archive ownership reporting changed the final executable IR")
    rows, edges = graph((work / "coverage.json").read_bytes())
    wrapper = next(helper for owner, helper, component, site in edges if component == "constant-archive")
    configuration = json.loads((work / "recipe.json").read_bytes())
    configuration["functions"][wrapper] = {"components": {"call-frames": "required"}}
    recipe = work / "transitive.json"; recipe.write_text(json.dumps(configuration), encoding="utf-8")
    output, report = work / "transitive.ll", work / "transitive-report.json"
    # Archive runtime source boundaries deliberately retain this call. A required
    # nested adapter cannot be credited from a failed/partial compiler report.
    run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff", f"-pyobf-cff-config={recipe}",
        "-pyobf-cff-seed=731", f"-pyobf-cff-requests-input={work / 'merged.requests.json'}",
        f"-pyobf-cff-report={report}", "-verify-each", "-S", work / "prepared.ll", "-o", output], succeeds=False)
    failed = json.loads(report.read_bytes())
    refused = [row for row in failed["functions"] if row["function"] == wrapper]
    if output.exists() or len(refused) != 1 or refused[0].get("reason") != "call-frames has zero eligible required sites" or \
            "generated_ownership" in failed:
        raise AssertionError("unsupported nested archive adapter received ownership/code credit")
