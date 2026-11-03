"""Actual ordinary emission receipts; never borrow a transformed object's inventory."""
from check_capture import ROOT, check_native
from cff_build import run
from function_inventory import Ownership, create, helpers
from generated_function_subject import generated_function_subject
from generated_ownership import graph
from pe_layout import parse_image


def check_untransformed(args, work, source, protected):
    plain, observed, report = (work / name for name in ("plain.ll", "observed.ll", "ordinary-inventory.json"))
    command = [args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-untransformed-ownership",
        f"-pyobf-cff-report={report}", "-verify-each", "-S"]
    run([args.opt, "-passes=verify", "-S", source, "-o", plain])
    run([*command, source, "-o", observed])
    if plain.read_bytes() != observed.read_bytes(): raise AssertionError("ordinary ownership inventory mutated executable IR")
    rows, edges = graph(report.read_bytes())
    if edges or any(row["selected"] for row in rows.values()) or not rows["owned_root"]["retained"]:
        raise AssertionError("ordinary inventory claimed transformed helpers or lost its actual root")
    native, binary = work / "ordinary.obj", work / "ordinary.dll"
    run([args.compiler, "-O0", "-fno-lto", "-ffunction-sections", "-c", source, "-o", native])
    run([args.compiler, "-shared", "-fno-lto", native, ROOT / "tests/measurement/generated_support.cpp", "-o", binary])
    obj, data = native.read_bytes(), binary.read_bytes()
    proof = Ownership(create(obj, source.read_bytes(), report.read_bytes()), report.read_bytes())
    if helpers(obj, proof, "owned_root"): raise AssertionError("ordinary compiler receipt invented generated helper code")
    subject = generated_function_subject(obj, data, parse_image(data), 0x631, "owned_root", proof)
    if len(subject.ranges) != 1: raise AssertionError("ordinary subject lost its independently emitted root extent")
    check_native(args.probe, args.runtime_directory, work, binary, data, parse_image(data), subject)
    before = report.read_bytes()
    run([*command, protected, "-o", work / "refused-inventory.ll"], succeeds=False)
    if report.read_bytes() != before or (work / "refused-inventory.ll").exists():
        raise AssertionError("transformed code overwrote an ordinary inventory receipt")
