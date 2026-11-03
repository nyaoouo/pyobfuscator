"""Refuse real valid-IR and final-image mutations using the production owner gates."""
import copy
import json
import re
import struct
import sys

from cff_build import run
from coff_symbols import image_symbols
from owner_reader_image import verify_owner_readers
from owner_reader_plan import readers
from pe_layout import parse_image, rva_section


def source_refusals(args, directory, unit, report, plan):
    source = unit.read_text()
    first = json.loads(report.read_text())["owner_readers"]["entries"][0]
    key = readers(plan)[0].key
    signed_key = key if key < 1 << 63 else key - (1 << 64)

    def changed(pattern, replacement):
        result, count = re.subn(pattern, replacement, source, count=1)
        if count != 1 or result == source: raise AssertionError(f"missing owner mutation anchor: {pattern}")
        return result

    read = re.search(r"(?m)^  (%\w+) = load volatile i8, ptr (%\w+),", source)
    span = re.search(r"(?m)^  (%\w+) = call [^\n]*@[^\n]*platform9code_span[^\n]*\n  store ptr \1, ptr (%\w+),[^\n]+\n", source)
    if not read or not span: raise AssertionError("actual generated capture mutation anchors are absent")
    load, pointer = read.groups()
    mutations = {
        "nonvolatile": changed(r"load volatile i8", "load i8"),
        "unmapped": changed(rf"load volatile i8, ptr {re.escape(pointer)},", "load volatile i8, ptr null,"),
        "discarded-byte": changed(rf"store i8 {re.escape(load)},", "store i8 0,"),
        "wrong-sha-input": changed(r"(platform11hash_sha256[^\n]*\(ptr noundef )%\w+", r"\g<1>null"),
        "wrong-sha-output": changed(r"(platform11hash_sha256[^\n]*, ptr noundef )%\w+", r"\g<1>null"),
        "wrong-key": changed(rf"(icmp (?:eq|ne) i64 %\w+, ){signed_key}\b", r"\g<1>0"),
        "aliased-callback": changed(rf"(ptr ){re.escape('@' + first['capture'])}(?=, ptr)", r"\g<1>@" + first["cache"]),
        "missing-cache-role": changed(r"owner\.cache\.v1:", "owner.xxxxx.v1:"),
    }
    # An opaque write to the actual mapped-pointer stack slot must invalidate its provenance.
    address = span.group(2)
    line = f"  call void @llvm.memcpy.p0.p0.i64(ptr align 8 {address}, ptr align 8 {address}, i64 8, i1 false)\n"
    mutations["clobbered-span-slot"] = source[:span.end()] + line + source[span.end():]
    mutations["repeated-span-copy"] = source[:span.end()] + line * 2 + source[span.end():]
    thin = directory / "owner-thin.cpp"
    original = (directory / "owner_readers.cpp").read_text()
    text, count = re.subn(r"return capture_owner<[^\n]+;", "return capture(input, member);", original, count=1)
    if count != 1: raise AssertionError("missing actual generated capture source")
    thin.write_text(text, encoding="utf-8")
    from check_capture import ROOT
    unit = directory / "owner-thin.ll"
    run([args.compiler, "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
        "-I", ROOT / "include", "-I", ROOT / "src", "-I", directory, thin, "-o", unit])
    mutations["thin-shared-capture"] = unit.read_text()
    for label, text in mutations.items():
        mutant = directory / f"owner-refuse-{label}.ll"
        mutant.write_text(text, encoding="utf-8")
        run([args.opt, "-passes=verify", "-disable-output", mutant])
        refused = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
            "-verify-each", "-disable-output", mutant], succeeds=False)
        if "owner reader" not in refused.stderr:
            raise AssertionError(f"{label} failed outside the owner contract: {refused.stderr}")
    print("valid-IR owner refusals:", ", ".join(mutations))


def image_refusals(args, directory, binary, report_path, object_path, manifest_path, plan, plan_path):
    data, report_bytes = binary.read_bytes(), report_path.read_bytes()
    report, obj, manifest = json.loads(report_bytes), object_path.read_bytes(), manifest_path.read_bytes()
    proof = verify_owner_readers(data, report, report_bytes, obj, manifest, plan)

    def refuse(label, image=data, candidate=report, raw=report_bytes, emission=obj, receipt=manifest, expected=plan):
        try: verify_owner_readers(image, candidate, raw, emission, receipt, expected)
        except ValueError: return
        raise AssertionError(f"owner final mutation escaped: {label}")

    def report_mutation(label, change):
        candidate = copy.deepcopy(report); change(candidate["owner_readers"])
        raw = json.dumps(candidate).encode()
        receipt = json.loads(manifest)
        import hashlib
        receipt["report_sha256"] = hashlib.sha256(raw).hexdigest()
        refuse(label, candidate=candidate, raw=raw, receipt=json.dumps(receipt).encode())

    report_mutation("missing-role", lambda p: p["entries"].pop())
    report_mutation("duplicate-role", lambda p: p["entries"][1].update(capture=p["entries"][0]["capture"]))
    report_mutation("wrong-owner", lambda p: p["entries"][0].update(owner=12345))
    report_mutation("unproved-read", lambda p: p["entries"][0].update(ir_mapped_bytes_to_sha_verified=False))
    refuse("stale-object", emission=obj + b"\0")
    image = parse_image(data)
    for label, rva in (("binding-key", proof["entries"][0]["binding_rva"] + 8),
                       ("binding-route", proof["entries"][0]["binding_rva"] + 16),
                       ("capture-code", proof["entries"][0]["capture_rva"]),
                       ("cache-code", proof["entries"][0]["cache_rva"])):
        part = rva_section(image, rva, 1)
        changed = bytearray(data); changed[part.raw_offset + rva - part.rva] ^= 1
        refuse(label, image=bytes(changed))
    symbols = {item.name: item for item in image_symbols(data, image)}
    first, second = (symbols[row["capture"]] for row in proof["entries"][:2])
    pe = struct.unpack_from("<I", data, 60)[0]
    table = struct.unpack_from("<I", data, pe + 12)[0]
    changed = bytearray(data)
    struct.pack_into("<Ih", changed, table + 18 * second.index + 8, first.value, first.section)
    refuse("folded-final-symbol", image=bytes(changed))
    for missing in ("--owner-object", "--owner-inventory", "--owner-plan"):
        inputs = {"--owner-object": object_path, "--owner-inventory": manifest_path, "--owner-plan": plan_path}
        inputs.pop(missing)
        from check_capture import ROOT
        result = run([sys.executable, ROOT / "demo/check_linked_cff.py", args.objdump, binary, report_path,
            *[value for pair in inputs.items() for value in pair]], succeeds=False)
        if "requires its actual object" not in result.stderr: raise AssertionError("owner CLI failed outside its input gate")
    print("owner final refusals: role/domain/flow, stale object, readonly key/route, both code bodies, folding, missing CLI inputs")
