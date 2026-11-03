"""Paired existing-context observer policy/range/owner costs, using existing size/hash helpers."""
import json
from pathlib import Path
from statistics import median
import struct
import sys

from check_reference import WORDS
from check_functions import prepare_fixture
from code_reference import build_reference
from code_subject import text_subject
from function_subject import function_subject
from pe_layout import parse_image
from reference_identity import Identity, identity_bytes
from cff_build import run, verify_image

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "demo"))
from measure_cff import digest, text_size


def measure(args, directory, combined, native, report):
    includes = ["-I", ROOT / "include", "-I", ROOT / "src"]
    _, fragments, dll = prepare_fixture(args.compiler, directory)
    raw = dll.read_bytes(); image = parse_image(raw)
    subjects = (text_subject(image, 0x901), function_subject(fragments.read_bytes(), raw, image,
        0x902, "extent_split", aliases=("extent_alias",), fragments=("extent_cold",)))
    binaries = {}
    for name, source in (("plain", combined), ("protected", native)):
        binary = directory / f"{name}-cost.exe"
        run([args.compiler, "-std=c++17", "-O2", source, ROOT / "tests/measurement/observer_cost.cpp",
            *args.backend, *includes, *(["-flto=thin"] if args.ipo else []), "-lbcrypt", "-o", binary])
        if name == "protected":
            verify_image([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump],
                binary, report, directory / "cost.final.json")
        binaries[name] = binary
    rows = []
    for subject in subjects:
        packages = []
        for owner in range(7, 11):
            identity = Identity(bytes(range(1, 17)), bytes(range(17, 33)), owner, subject.tag,
                1 if subject.kind == "section" else 3, 1, 4096)
            metadata, package = directory / f"{owner}.meta", directory / f"{owner}.bin"
            metadata.write_bytes(identity_bytes(identity) + struct.pack("<8I", *WORDS))
            package.write_bytes(build_reference(raw, subject, identity, WORDS)); packages.append(digest(package))
        costs = {}
        for name, binary in binaries.items():
            values = {}
            for line in run([binary, directory, dll]).stdout.splitlines():
                if not line.startswith("cost "): continue
                _, mode, count, cold, ns = line.split()
                values.setdefault(f"{mode}/{count}/{'cold' if cold == '1' else 'hot'}", []).append(float(ns))
            if len(values) != 12 or any(len(value) != 7 or min(value) <= 0 for value in values.values()):
                raise AssertionError("observer paired costs lack all policy/owner/hotness batches")
            costs[name] = {"image_sha256": digest(binary), "text_bytes": text_size(args.objdump, binary),
                "median_group_ns": {key: median(value) for key, value in values.items()}}
        rows.append({"subject": subject.kind, "bytes": sum(span.size for span in subject.ranges),
            "package_sha256": packages, "costs": costs})
    args.measure_output.write_text(json.dumps({"scope": "same loaded DLL; modes0once/1bounded/2per-use,1or4distinct owners; hot observe+consume+retire vs cold create+first use+all cleanup",
        "optimization": args.optimization, "parent_ipo": args.ipo, "batches": 7, "groups_per_batch": 32,
        "compiler": run([args.compiler, "--version"]).stdout.splitlines()[0],
        "source_ir_sha256": digest(combined), "protected_object_sha256": digest(native),
        "sample_sha256": digest(dll), "subjects": rows}, indent=2) + "\n")
