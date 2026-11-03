"""Exercise the creator source gate and its exact final-image contribution."""
import copy
import hashlib
import json
import re
import struct

from cff_build import run
from coff_symbols import image_symbols
from owner_creator_image import verify_owner_creators
from owner_reader_image import verify_owner_readers
from pe_layout import parse_image, rva_section


def source_refusals(args, directory, unit, report_path):
    source = unit.read_text()
    creators = [row["function"] for row in json.loads(report_path.read_text())["owner_creators"]["entries"]]
    first, second = (re.escape(name) for name in creators[:2])
    body = re.search(rf"(?s)define [^\n]*@{first}\([^\n]*\) [^\n]*\{{\n.*?\n\}}", source)
    if body is None: raise AssertionError("generated creator body is absent from the real test IR")

    def change_body(pattern, replacement):
        changed, count = re.subn(pattern, replacement, body.group(), count=1)
        if count != 1 or changed == body.group(): raise AssertionError(f"missing creator mutation anchor: {pattern}")
        return source[:body.start()] + changed + source[body.end():]

    row = re.search(r"(?m)^  store ptr (@pyobf_native_owner_bindings_\w+), ptr (%\w+),[^\n]*", body.group())
    call = re.search(r"(?m)^  call void @(_ZN[^\n(]*observer6create[^\n(]*)\([^\n]+", body.group())
    spec = re.search(r"(?m)^  (%\w+) = alloca %\"struct\.pyobfuscator::native::measurement::observer::Spec\"", body.group())
    if row is None or call is None or spec is None:
        raise AssertionError("generated creator lacks fixed row, local Spec or direct create")
    table, slot = row.groups()
    target = call.group(1)
    mutations = {
        "wrong-binding-row": change_body(r"(?m)^  store ptr " + re.escape(table) + r", ptr " + re.escape(slot),
            "  store ptr getelementptr (i8, ptr " + table + ", i64 32), ptr " + slot),
        "clobbered-reader": change_body(r"(?m)^  store ptr " + re.escape(table) + r", ptr " + re.escape(slot) + r",[^\n]*",
            row.group() + "\n  store ptr null, ptr " + slot + ", align 8"),
        "opaque-spec-mutator": change_body(r"(?m)^  call void @" + re.escape(target),
            "  call void @pyobf_test_spec_mutator(ptr " + spec.group(1) + ")\n  call void @" + target) +
            "\ndeclare void @pyobf_test_spec_mutator(ptr)\n",
    }
    declaration = re.search(rf"(?m)^declare [^\n]*@{re.escape(target)}\([^\n]+$", source)
    if declaration is None: raise AssertionError("actual observer declaration is absent")
    fake = "pyobf_test_discard_creation"
    mutations["missing-direct-create"] = change_body(r"(?m)^  call void @" + re.escape(target),
        "  call void @" + fake) + "\n" + declaration.group().replace("@" + target, "@" + fake) + "\n"
    changed, count = re.subn(r"(?m)^  call void @" + first + r"(?=\()", "  call void @" + creators[1], source, count=1)
    if count != 1: raise AssertionError("selected producer has no direct first creator call")
    mutations["unused-creator"] = changed
    changed, count = re.subn(r"(?m)^  call void @" + second + r"(?=\()", "  call void @" + creators[0], source, count=1)
    if count != 1: raise AssertionError("selected producer has no direct second creator call")
    nested = "  call void @" + creators[1] + \
        "(ptr sret(%\"struct.pyobfuscator::native::measurement::observer::Creation\") %0, " + \
        "ptr %1, i64 %2, ptr %3, ptr %4, ptr %5, ptr %6, i64 %7)\n"
    nested_body = body.group().replace(call.group(), nested + call.group(), 1)
    mutations["creator-only-use"] = changed[:body.start()] + nested_body + changed[body.end():]
    raw = "\ndefine void @pyobf_test_raw_creator_bypass() {\nentry:\n  call void @" + target + \
        "(ptr sret(%\"struct.pyobfuscator::native::measurement::observer::Creation\") null, ptr null, " + \
        "i64 0, ptr null, ptr null, ptr null)\n  ret void\n}\n"
    mutations["raw-create-bypass"] = source + raw
    for label, candidate in mutations.items():
        mutant = directory / f"creator-refuse-{label}.ll"
        mutant.write_text(candidate, encoding="utf-8")
        run([args.opt, "-passes=verify", "-disable-output", mutant])
        refused = run([args.opt, f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
            "-verify-each", "-disable-output", mutant], succeeds=False)
        if "owner creator:" not in refused.stderr:
            raise AssertionError(f"{label} failed outside the creator source contract: {refused.stderr}")
    print("valid-IR creator refusals:", ", ".join(mutations))


def image_refusals(directory, binary, report_path, object_path, manifest_path, plan):
    data, report_bytes = binary.read_bytes(), report_path.read_bytes()
    report, obj, manifest = json.loads(report_bytes), object_path.read_bytes(), manifest_path.read_bytes()
    reader_proof = verify_owner_readers(data, report, report_bytes, obj, manifest, plan)
    proof = verify_owner_creators(data, report, report_bytes, obj, manifest, plan, reader_proof)

    def refuse(label, image=data, candidate=report, raw=report_bytes, emission=obj, receipt=manifest):
        try: verify_owner_creators(image, candidate, raw, emission, receipt, plan, reader_proof)
        except ValueError: return
        raise AssertionError(f"creator final mutation escaped: {label}")

    def mutate_report(label, edit):
        candidate = copy.deepcopy(report)
        edit(candidate["owner_creators"])
        raw = json.dumps(candidate).encode()
        receipt = json.loads(manifest)
        receipt["report_sha256"] = hashlib.sha256(raw).hexdigest()
        refuse(label, candidate=candidate, raw=raw, receipt=json.dumps(receipt).encode())

    mutate_report("missing-role", lambda p: p["entries"].pop())
    mutate_report("wrong-owner", lambda p: p["entries"][0].update(owner=12345))
    mutate_report("unproved-row", lambda p: p["entries"][0].update(fixed_binding_row_verified=False))
    mutate_report("shared-creator", lambda p: p["entries"][1].update(function=p["entries"][0]["function"]))
    refuse("stale-object", emission=obj + b"\0")
    image = parse_image(data)
    for entry in proof["entries"]:
        rva = entry["ranges"][0]["rva"]
        part = rva_section(image, rva, 1)
        changed = bytearray(data)
        changed[part.raw_offset + rva - part.rva] ^= 1
        refuse(f"creator-code-{entry['index']}", image=bytes(changed))
    symbols = {item.name: item for item in image_symbols(data, image)}
    first, second = (symbols[entry["function"]] for entry in proof["entries"][:2])
    pe = struct.unpack_from("<I", data, 60)[0]
    table = struct.unpack_from("<I", data, pe + 12)[0]
    changed = bytearray(data)
    struct.pack_into("<Ih", changed, table + 18 * second.index + 8, first.value, first.section)
    refuse("folded-final-creator-symbol", image=bytes(changed))
    print("creator final refusals: role, row, sharing, stale object, each code body and folded symbol")
