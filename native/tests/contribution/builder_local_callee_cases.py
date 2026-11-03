"""Check actual mixed binding callees and a receipt-matched status bypass."""

import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"), str(Path(__file__).resolve().parent)]

from builder_replay_cases import changed_cmov  # noqa: E402
from builder_subject_cases import root, symbol_section_mutation  # noqa: E402
from cff_builder_local_callees import (  # noqa: E402
    BINDING_STATUS, LOCAL_CALLEES, REQUIRE_BINDING, verify_builder_local_callees,
)
from cff_builder_receipt import ROLES, create_receipt, verify_receipt  # noqa: E402
from cff_joint_machine_evidence import MEASURED, OWNED  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from function_subject import function_subject  # noqa: E402
from pe_layout import data_directory, parse_image, read_rva, rva_section  # noqa: E402


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), f"{label}: wrong refusal: {error}"
        return
    raise AssertionError(f"{label}: altered input was accepted")


def cache_value(build, key):
    matches = [line.split("=", 1)[1] for line in (build / "CMakeCache.txt").read_text(
        encoding="utf-8").splitlines() if line.startswith(key + ":")]
    assert len(matches) == 1, f"missing or repeated CMake cache entry: {key}"
    return matches[0]


def inputs_for(build):
    demo = build / "demo"
    paths = {"image": demo / "libpyobf_native_demo_inner.dll",
             "report": demo / "payload.cff.coverage.json",
             "private": demo / "payload.binding.private.json",
             "plan": demo / "payload.post-mixed.edges.json",
             "object": demo / "payload.cff.obj"}
    fixed = json.loads((build / "builder.fixed.json").read_text(encoding="utf-8"))
    candidates = (demo / "payload.requested.ll", demo / "payload.archive.prepared.ll")
    matches = [path for path in candidates if path.is_file() and
               hashlib.sha256(path.read_bytes()).hexdigest() == fixed["inputs"]["input_ir"]]
    assert len(matches) == 1
    paths["input_ir"] = matches[0]
    assert set(paths) == set(ROLES)
    return paths


def disassembly(objdump, image, name):
    result = subprocess.run([str(objdump), "-d", f"--disassemble-symbols={name}",
                             str(image)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return result.stdout.lower()


def changed_pre_call_scope(object_bytes, image_bytes, optimization):
    pattern = (bytes.fromhex("488b442430") if optimization == "none"
               else bytes.fromhex("488b542430"))
    obj = parse_object(object_bytes)
    section = obj.sections[root(obj, REQUIRE_BINDING).section - 1]
    offsets = [offset for offset in range(section.size - len(pattern) + 1)
               if object_bytes[section.offset + offset:
                               section.offset + offset + len(pattern)] == pattern]
    assert len(offsets) == 1, "expected one pre-call Scope/lease stack read"
    offset = offsets[0]
    assert all(not (relocation.offset < offset + len(pattern) and offset < relocation.offset +
                    (8 if relocation.kind == 1 else 4)) for relocation in section.relocations)
    image = parse_image(image_bytes)
    subject = function_subject(object_bytes, image_bytes, image, 0xb510, REQUIRE_BINDING)
    assert len(subject.ranges) == 1
    rva = subject.ranges[0].rva
    pe_section = rva_section(image, rva, section.size, logical=True)
    start = pe_section.raw_offset + rva - pe_section.rva
    assert image_bytes[start + offset:start + offset + len(pattern)] == pattern
    changed_object, changed_image = bytearray(object_bytes), bytearray(image_bytes)
    changed_object[section.offset + offset + 4] = 0x38
    changed_image[start + offset + 4] = 0x38
    return bytes(changed_object), bytes(changed_image)


def changed_frame_escape(object_bytes, image_bytes, optimization):
    patterns = (("48894c2440", "488b4c2440", 0x60) if optimization == "none"
                else ("4889542430", "488b542430", 0x48))
    obj = parse_object(object_bytes)
    section = obj.sections[root(obj, REQUIRE_BINDING).section - 1]
    image = parse_image(image_bytes)
    subject = function_subject(object_bytes, image_bytes, image, 0xb511, REQUIRE_BINDING)
    assert len(subject.ranges) == 1
    rva = subject.ranges[0].rva
    pe_section = rva_section(image, rva, section.size, logical=True)
    start = pe_section.raw_offset + rva - pe_section.rva
    changed_object, changed_image = bytearray(object_bytes), bytearray(image_bytes)
    for spelling in patterns[:2]:
        pattern = bytes.fromhex(spelling)
        offsets = [offset for offset in range(section.size - len(pattern) + 1)
                   if object_bytes[section.offset + offset:
                                   section.offset + offset + len(pattern)] == pattern]
        assert len(offsets) == 1, "expected one exact stack write/read in local function"
        offset = offsets[0]
        assert all(not (relocation.offset < offset + len(pattern) and
                        offset < relocation.offset + (8 if relocation.kind == 1 else 4))
                   for relocation in section.relocations)
        assert image_bytes[start + offset:start + offset + len(pattern)] == pattern
        changed_object[section.offset + offset + 4] = patterns[2]
        changed_image[start + offset + 4] = patterns[2]
    return bytes(changed_object), bytes(changed_image)


def changed_dispatcher_alias(object_bytes, image_bytes):
    obj = parse_object(object_bytes)
    section = obj.sections[root(obj, REQUIRE_BINDING).section - 1]
    image = parse_image(image_bytes)
    subject = function_subject(object_bytes, image_bytes, image, 0xb512, REQUIRE_BINDING)
    assert len(subject.ranges) == 1
    rva = subject.ranges[0].rva
    pe_section = rva_section(image, rva, section.size, logical=True)
    start = pe_section.raw_offset + rva - pe_section.rva
    changed_object, changed_image = bytearray(object_bytes), bytearray(image_bytes)
    for spelling, count in (("8944242c", 1), ("8b44242c", 2)):
        pattern = bytes.fromhex(spelling)
        offsets = [offset for offset in range(section.size - len(pattern) + 1)
                   if object_bytes[section.offset + offset:
                                   section.offset + offset + len(pattern)] == pattern]
        assert len(offsets) == count, "expected exact dispatcher temporary write/read sites"
        for offset in offsets:
            assert all(not (relocation.offset < offset + len(pattern) and
                            offset < relocation.offset + (8 if relocation.kind == 1 else 4))
                       for relocation in section.relocations)
            assert image_bytes[start + offset:start + offset + len(pattern)] == pattern
            changed_object[section.offset + offset + 3] = 0x30
            changed_image[start + offset + 3] = 0x30
    return bytes(changed_object), bytes(changed_image)


def changed_state_shadow(object_bytes, image_bytes, optimization):
    displacement = "54" if optimization == "none" else "44"
    obj = parse_object(object_bytes)
    section = obj.sections[root(obj, REQUIRE_BINDING).section - 1]
    image = parse_image(image_bytes)
    subject = function_subject(object_bytes, image_bytes, image, 0xb513, REQUIRE_BINDING)
    assert len(subject.ranges) == 1
    rva = subject.ranges[0].rva
    pe_section = rva_section(image, rva, section.size, logical=True)
    start = pe_section.raw_offset + rva - pe_section.rva
    changed_object, changed_image = bytearray(object_bytes), bytearray(image_bytes)
    for prefix, count in (("c74424", 1), ("8b4424", 2), ("894424", 1)):
        pattern = bytes.fromhex(prefix + displacement)
        offsets = [offset for offset in range(section.size - len(pattern) + 1)
                   if object_bytes[section.offset + offset:
                                   section.offset + offset + len(pattern)] == pattern]
        assert len(offsets) == count, "expected exact state initializer/read/write sites"
        for offset in offsets:
            assert all(not (relocation.offset < offset + len(pattern) and
                            offset < relocation.offset + (8 if relocation.kind == 1 else 4))
                       for relocation in section.relocations)
            assert image_bytes[start + offset:start + offset + len(pattern)] == pattern
            changed_object[section.offset + offset + 3] = 0x1c
            changed_image[start + offset + 3] = 0x1c
    return bytes(changed_object), bytes(changed_image)


def finalizer(build, paths, output, receipt, *, local):
    demo = build / "demo"
    command = [sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
               cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE"),
               str(paths["image"]), str(paths["report"]), "--output", str(output),
               "--post-mixed-plan", str(paths["plan"]),
               "--post-mixed-private", str(paths["private"]),
               "--post-mixed-material", str(demo / "release-material.private.json"),
               "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
               "--builder-receipt", str(receipt),
               "--builder-input-ir", str(paths["input_ir"]),
               "--builder-object", str(paths["object"]),
               "--builder-subjects", "--builder-entry-states"]
    if local:
        command.extend(("--builder-local-callees", "--builder-local-callees-seed",
                        cache_value(build, "PYOBF_NATIVE_CFF_SEED")))
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=40)


def check_scope_swap(build):
    paths = inputs_for(build)
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    changed_object, changed_image = changed_pre_call_scope(
        inputs["object"], inputs["image"], optimization)
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        changed_paths = {**paths, "object": temp / "changed.obj", "image": temp / "changed.dll"}
        changed_paths["object"].write_bytes(changed_object)
        changed_paths["image"].write_bytes(changed_image)
        receipt = temp / "changed.receipt.json"
        receipt.write_bytes(create_receipt(
            {role: path.read_bytes() for role, path in changed_paths.items()}))
        old = finalizer(build, changed_paths, temp / "old.final.json", receipt, local=False)
        current_output = temp / "current.final.json"
        current_output.write_bytes(b"stale")
        current = finalizer(build, changed_paths, current_output, receipt, local=True)
        assert old.returncode == 0 and (temp / "old.final.json").exists(), old.stderr
        assert current.returncode != 0 and not current_output.exists(), current.stderr
        assert ("builder local callee proof failed" in current.stderr and
                "binding status call lost its entry Scope or lease identity" in current.stderr and
                "builder receipt verification failed" not in current.stderr), current.stderr
    print(f"scope swap {optimization}: old receipt/finalizer admits, exact local identity route refuses")


def check_frame_escape(build):
    paths = inputs_for(build)
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    changed_object, changed_image = changed_frame_escape(
        inputs["object"], inputs["image"], optimization)
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        changed_paths = {**paths, "object": temp / "changed.obj", "image": temp / "changed.dll"}
        changed_paths["object"].write_bytes(changed_object)
        changed_paths["image"].write_bytes(changed_image)
        changed_inputs = {role: path.read_bytes() for role, path in changed_paths.items()}
        receipt = temp / "changed.receipt.json"
        receipt.write_bytes(create_receipt(changed_inputs))
        assert verify_receipt(receipt.read_bytes(), changed_inputs)["verified"] is True
        old = finalizer(build, changed_paths, temp / "old.final.json", receipt, local=False)
        current_output = temp / "current.final.json"
        current_output.write_bytes(b"stale")
        current = finalizer(build, changed_paths, current_output, receipt, local=True)
        assert old.returncode == 0 and (temp / "old.final.json").exists(), old.stderr
        assert current.returncode != 0 and not current_output.exists(), current.stderr
        assert ("builder local callee proof failed" in current.stderr and
                ("binding pre-call copy leaves its fixed frame" if optimization == "none"
                 else "binding entry argument spills alias each other or dispatcher state")
                in current.stderr and
                "builder receipt verification failed" not in current.stderr), current.stderr
    print(f"frame escape {optimization}: old receipt/finalizer admits, local frame gate refuses")


def check_dispatcher_alias(build):
    paths = inputs_for(build)
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    changed_object, changed_image = changed_dispatcher_alias(
        inputs["object"], inputs["image"])
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        changed_paths = {**paths, "object": temp / "changed.obj", "image": temp / "changed.dll"}
        changed_paths["object"].write_bytes(changed_object)
        changed_paths["image"].write_bytes(changed_image)
        changed_inputs = {role: path.read_bytes() for role, path in changed_paths.items()}
        receipt = temp / "changed.receipt.json"
        receipt.write_bytes(create_receipt(changed_inputs))
        assert verify_receipt(receipt.read_bytes(), changed_inputs)["verified"] is True
        old = finalizer(build, changed_paths, temp / "old.final.json", receipt, local=False)
        current_output = temp / "current.final.json"
        current_output.write_bytes(b"stale")
        current = finalizer(build, changed_paths, current_output, receipt, local=True)
        assert old.returncode == 0 and (temp / "old.final.json").exists(), old.stderr
        assert current.returncode != 0 and not current_output.exists(), current.stderr
        assert ("builder local callee proof failed" in current.stderr and
                "binding dispatcher has an unknown copied state" in current.stderr and
                "builder receipt verification failed" not in current.stderr), current.stderr
    print("dispatcher alias: old receipt/finalizer admits, local spill-isolation gate refuses")


def check_state_shadow(build):
    paths = inputs_for(build)
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    changed_object, changed_image = changed_state_shadow(
        inputs["object"], inputs["image"], optimization)
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        changed_paths = {**paths, "object": temp / "changed.obj", "image": temp / "changed.dll"}
        changed_paths["object"].write_bytes(changed_object)
        changed_paths["image"].write_bytes(changed_image)
        changed_inputs = {role: path.read_bytes() for role, path in changed_paths.items()}
        receipt = temp / "changed.receipt.json"
        receipt.write_bytes(create_receipt(changed_inputs))
        assert verify_receipt(receipt.read_bytes(), changed_inputs)["verified"] is True
        old = finalizer(build, changed_paths, temp / "old.final.json", receipt, local=False)
        current_output = temp / "current.final.json"
        current_output.write_bytes(b"stale")
        current = finalizer(build, changed_paths, current_output, receipt, local=True)
        assert old.returncode == 0 and (temp / "old.final.json").exists(), old.stderr
        assert current.returncode != 0 and not current_output.exists(), current.stderr
        assert ("builder local callee proof failed" in current.stderr and
                "binding dispatcher state or outgoing call area leaves its fixed frame"
                in current.stderr and
                "builder receipt verification failed" not in current.stderr), current.stderr
    print(f"state shadow {optimization}: old receipt/finalizer admits, local frame gate refuses")


def check_unwind_allocation(build):
    paths = inputs_for(build)
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    image = parse_image(inputs["image"])
    span = function_subject(inputs["object"], inputs["image"], image,
                            0xb520, REQUIRE_BINDING).ranges[0]
    directory, size = data_directory(image, 3)
    rows = tuple(struct.iter_unpack("<III", read_rva(inputs["image"], image, directory, size)))
    matching = [unwind for begin, end, unwind in rows
                if begin == span.rva and end == span.rva + span.size]
    assert len(matching) == 1
    unwind = matching[0]
    assert read_rva(inputs["image"], image, unwind, 4) == b"\x01\x04\x01\x00"
    allocation_code = read_rva(inputs["image"], image, unwind + 5, 1)[0]
    assert allocation_code in (0x82, 0xa2)
    section = rva_section(image, unwind + 5, 1, logical=True)
    offset = section.raw_offset + unwind + 5 - section.rva
    changed_image = bytearray(inputs["image"])
    changed_image[offset] ^= 0x10
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        changed_paths = {**paths, "image": temp / "changed.dll"}
        changed_paths["image"].write_bytes(changed_image)
        changed_inputs = {role: path.read_bytes() for role, path in changed_paths.items()}
        receipt = temp / "changed.receipt.json"
        receipt.write_bytes(create_receipt(changed_inputs))
        assert verify_receipt(receipt.read_bytes(), changed_inputs)["verified"] is True
        old = finalizer(build, changed_paths, temp / "old.final.json", receipt, local=False)
        current_output = temp / "current.final.json"
        current_output.write_bytes(b"stale")
        current = finalizer(build, changed_paths, current_output, receipt, local=True)
        assert old.returncode == 0 and (temp / "old.final.json").exists(), old.stderr
        assert current.returncode != 0 and not current_output.exists(), current.stderr
        assert ("builder local callee proof failed" in current.stderr and
                "binding frame allocation differs from PE unwind codes" in current.stderr and
                "builder receipt verification failed" not in current.stderr), current.stderr
    print("unwind allocation: old receipt/finalizer admits, exact PE frame gate refuses")


def check(build):
    paths = inputs_for(build)
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    assert verify_receipt((build / "builder.fixed.json").read_bytes(), inputs)["verified"] is True
    seed = int(cache_value(build, "PYOBF_NATIVE_CFF_SEED"))
    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    assert optimization in ("none", "O2")
    objdump = cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    helpers = {name: disassembly(objdump, paths["image"], name)
               for name in (OWNED, MEASURED)}
    locals_ = {name: disassembly(objdump, paths["image"], name)
               for name in LOCAL_CALLEES}
    proof = verify_builder_local_callees(inputs["object"], inputs["image"],
                                         inputs["report"], seed, helpers, locals_)
    assert proof == json.loads((build / "demo" / "payload.cff.final.json").read_bytes())[
        "builder_local_callees"]
    assert proof["local_status_route_verified"] is True
    assert proof["status_zero_state"] != proof["status_nonzero_state"]
    assert [item["symbol"] for item in proof["subjects"]] == list(LOCAL_CALLEES)

    refused("wrong build seed", lambda: verify_builder_local_callees(
        inputs["object"], inputs["image"], inputs["report"], seed ^ 1,
        helpers, locals_), "independent build seed")
    changed_report = json.loads(inputs["report"])
    selected = next(row for row in changed_report["functions"]
                    if row["function"] == REQUIRE_BINDING)
    next(part for part in selected["effective_recipe"]["components"]
         if part["component"] == "cfg")["seed"] ^= 1
    refused("changed raw CFG seed", lambda: verify_builder_local_callees(
        inputs["object"], inputs["image"],
        json.dumps(changed_report).encode(), seed, helpers, locals_),
        "independent build seed")
    duplicate_report = inputs["report"].replace(b'"data_layout":',
        b'"data_layout":"fake","data_layout":', 1)
    assert duplicate_report != inputs["report"]
    refused("duplicate report key", lambda: verify_builder_local_callees(
        inputs["object"], inputs["image"], duplicate_report, seed,
        helpers, locals_), "duplicate JSON key")
    obj = parse_object(inputs["object"])
    missing = symbol_section_mutation(inputs["object"], root(obj, REQUIRE_BINDING), 0)
    refused("missing local COFF root", lambda: verify_builder_local_callees(
        missing, inputs["image"], inputs["report"], seed, helpers, locals_),
        "one offset-zero root definition")
    redirected = {**locals_, REQUIRE_BINDING: locals_[REQUIRE_BINDING].replace(
        BINDING_STATUS.lower(), "_zn12pyobfuscator6native8platform18protection_failureej")}
    refused("forged status target", lambda: verify_builder_local_callees(
        inputs["object"], inputs["image"], inputs["report"], seed, helpers,
        redirected), "exact status and failure calls")
    indirect = re.sub(rf"\bcallq?\t0x[0-9a-f]+ <{re.escape(BINDING_STATUS.lower())}>",
                      "callq\t*%rax", locals_[REQUIRE_BINDING], count=1)
    assert indirect != locals_[REQUIRE_BINDING]
    refused("indirect local call", lambda: verify_builder_local_callees(
        inputs["object"], inputs["image"], inputs["report"], seed, helpers,
        {**locals_, REQUIRE_BINDING: indirect}), "indirect or malformed call")
    unmodelled_store = re.sub(r"(\tmovq\t0x[0-9a-f]+\(%rsp\), )%[a-z0-9]+",
                              r"\1(%rcx)", locals_[REQUIRE_BINDING], count=1)
    assert unmodelled_store != locals_[REQUIRE_BINDING]
    refused("pre-call unknown memory store", lambda: verify_builder_local_callees(
        inputs["object"], inputs["image"], inputs["report"], seed, helpers,
        {**locals_, REQUIRE_BINDING: unmodelled_store}),
        "pre-call copy accesses unmodelled memory")
    malformed_cmp = re.sub(r"(\tcmpl\t\$0x[0-9a-f]+), %eax", r"\1",
                           locals_[REQUIRE_BINDING], count=1)
    assert malformed_cmp != locals_[REQUIRE_BINDING]
    refused("malformed dispatcher compare", lambda: verify_builder_local_callees(
        inputs["object"], inputs["image"], inputs["report"], seed, helpers,
        {**locals_, REQUIRE_BINDING: malformed_cmp}),
        "binding dispatcher has an unsupported instruction")

    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        changed_object, changed_image = changed_cmov(
            inputs["object"], inputs["image"], source_optimization=optimization)
        changed_paths = {**paths, "object": temp / "changed.obj", "image": temp / "changed.dll"}
        changed_paths["object"].write_bytes(changed_object)
        changed_paths["image"].write_bytes(changed_image)
        changed_inputs = {role: path.read_bytes() for role, path in changed_paths.items()}
        receipt = temp / "changed.receipt.json"
        receipt.write_bytes(create_receipt(changed_inputs))
        assert verify_receipt(receipt.read_bytes(), changed_inputs)["verified"] is True
        old_output = temp / "old.final.json"
        accepted = finalizer(build, changed_paths, old_output, receipt, local=False)
        assert accepted.returncode == 0 and old_output.exists(), accepted.stderr
        assert "builder_local_callees" not in json.loads(old_output.read_bytes())
        output = temp / "stale.final.json"
        output.write_bytes(b"stale")
        denied = finalizer(build, changed_paths, output, receipt, local=True)
        assert denied.returncode != 0 and not output.exists(), denied.stderr
        assert ("builder local callee proof failed" in denied.stderr and
                "binding status update has an unsupported instruction sequence" in denied.stderr and
                "builder receipt verification failed" not in denied.stderr), denied.stderr
        altered_codes = {name: disassembly(objdump, changed_paths["image"], name)
                         for name in LOCAL_CALLEES}
        refused("paired conditional-move removal", lambda: verify_builder_local_callees(
            changed_object, changed_image, inputs["report"], seed,
            {name: disassembly(objdump, changed_paths["image"], name)
             for name in (OWNED, MEASURED)}, altered_codes),
            "binding status update has an unsupported instruction sequence")
    check_scope_swap(build)
    check_frame_escape(build)
    check_dispatcher_alias(build)
    check_state_shadow(build)
    check_unwind_allocation(build)
    print(f"builder local callees: {optimization} exact PE/COFF and status route; "
          "paired control, identity and frame old-admit/new-refuse negatives passed")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
