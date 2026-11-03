"""Optional paired full-capture costs using the existing protected-core build."""
import json
from pathlib import Path
from statistics import median
import struct
import sys

from check_capture import descriptor
from code_subject import text_subject, unwind_interval
from pe_layout import data_directory, parse_image, read_rva
from pe_relocations import relocations

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "demo"))
from measure_cff import digest, text_size
from cff_build import run, verify_image


def measure(args, directory, combined, native, includes, report):
    if not args.sample: raise AssertionError("paired cost needs the same actual DLL subject")
    sample = args.sample[0].resolve(); raw = sample.read_bytes(); image = parse_image(raw)
    pdata, _ = data_directory(image, 3)
    entry = struct.unpack_from("<I", read_rva(raw, image, pdata, 12))[0]
    subjects = (text_subject(image, 0x201), unwind_interval(raw, image, 0x202, entry))
    costs = {}
    for name, core in (("plain", combined), ("protected", native)):
        measured = directory / f"{name}-cost.exe"
        run([args.compiler, "-std=c++17", "-O2", core, ROOT / "tests/measurement/cost.cpp",
            ROOT / "tests/measurement/descriptor.cpp", *args.backend, *includes, "-lbcrypt",
            *( ["-flto=thin"] if args.ipo else []), "-o", measured])
        if name == "protected":
            verify_image([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump],
                measured, report, directory / "cost.final.json")
        rows = {}
        for subject in subjects:
            parameter = directory / f"cost-{subject.kind}.bin"
            parameter.write_bytes(descriptor(image, subject, relocations(raw, image)))
            values = {1: [], 4: []}
            for line in run([measured, parameter, sample]).stdout.splitlines():
                owner, ns = line.split(); values[int(owner)].append(float(ns))
            if any(len(v) != 7 or min(v) <= 0 for v in values.values()):
                raise AssertionError("paired native acquisition costs lack seven positive batches")
            rows[subject.kind] = {"bytes": sum(span.size for span in subject.ranges),
                "median_group_ns": {str(k): median(v) for k, v in values.items()}}
        costs[name] = {"text_bytes": text_size(args.objdump, measured), "image_sha256": digest(measured), "subjects": rows}
    args.measure_output.write_text(json.dumps({"scope": "same loaded DLL, full native captures incl pin/validation/allocation/CNG/erase/release; no cache",
        "optimization": args.optimization, "parent_ipo": args.ipo, "batches": 7,
        "sample_sha256": digest(sample), "source_ir_sha256": digest(combined),
        "protected_object_sha256": digest(native), "compiler": run([args.compiler, "--version"]).stdout.splitlines()[0],
        "groups_per_batch": 32, "costs": costs}, indent=2) + "\n", encoding="utf-8")
