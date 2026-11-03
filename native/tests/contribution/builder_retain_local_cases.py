"""Exercise the selected retain-context routes on actual COFF and linked PE."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"), str(Path(__file__).resolve().parent)]

from builder_binding_status_effects_cases import paired_instruction  # noqa: E402
from builder_bound_call_cases import body_item, fixed_inputs  # noqa: E402
from builder_local_callee_cases import cache_value, disassembly, inputs_for  # noqa: E402
from cff_builder_bound_call import RETAIN  # noqa: E402
from cff_builder_receipt import create_receipt, verify_receipt  # noqa: E402
from cff_builder_retain_local import MAXIMUM_BODY, verify_builder_retain_local  # noqa: E402
from cff_joint_machine_evidence import Instruction, _instructions  # noqa: E402
from function_subject import function_subject  # noqa: E402
from pe_layout import parse_image  # noqa: E402


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), (label, error)
        return
    raise AssertionError(f"{label}: changed input was accepted")


def finalizer(build, paths, output, receipt, *, retain):
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
               "--builder-subjects", "--builder-entry-states", "--builder-local-callees",
               "--builder-local-callees-seed", cache_value(build, "PYOBF_NATIVE_CFF_SEED"),
               "--builder-helper-arguments", "--builder-binding-status-effects",
               "--builder-context-availability-effect", "--builder-bound-call"]
    if retain:
        command.append("--builder-retain-local")
    return subprocess.run(command, capture_output=True, text=True, timeout=90,
                          check=False)


def changed_codes(build, image_bytes):
    with TemporaryDirectory(dir=build) as directory:
        path = Path(directory) / "paired.dll"
        path.write_bytes(image_bytes)
        return {RETAIN: disassembly(
            cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE"), path, RETAIN)}


def paired_finalizer_case(build, paths, changed_object, changed_image, label):
    """Compare the local predecessor gate, not the fixed replay authority."""
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        altered = {**paths, "object": temp / "paired.obj", "image": temp / "paired.dll"}
        altered["object"].write_bytes(changed_object)
        altered["image"].write_bytes(changed_image)
        data = {role: path.read_bytes() for role, path in altered.items()}
        receipt = temp / "paired.receipt.json"
        receipt.write_bytes(create_receipt(data))
        assert verify_receipt(receipt.read_bytes(), data)["verified"] is True
        predecessor = finalizer(build, altered, temp / "predecessor.json", receipt,
                                retain=False)
        assert predecessor.returncode == 0 and (temp / "predecessor.json").exists(), \
            (label, predecessor.stderr)
        output = temp / "stale.json"
        output.write_bytes(b"stale")
        current = finalizer(build, altered, output, receipt, retain=True)
        assert current.returncode != 0 and not output.exists(), (label, current.stderr)
        assert ("builder retain local route proof failed:" in current.stderr and
                "builder receipt verification failed:" not in current.stderr), \
            (label, current.stderr)
    print(f"{label}: local predecessor admits; retain gate refuses and clears stale output")


def check(build):
    paths = inputs_for(build)
    data = {role: path.read_bytes() for role, path in paths.items()}
    objdump = cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    codes = {RETAIN: disassembly(objdump, paths["image"], RETAIN)}
    proof = verify_builder_retain_local(data["object"], data["image"],
                                        data["report"], codes)
    assert proof == {
        "verified": True, "selected_retain_route_verified": True,
        "closing_guard_verified": True, "reference_limit_guard_verified": True,
        "increment_store_verified": True, "status_route_verified": True,
        "lock_pair_route_verified": True, "full_retain_effect_verified": False,
        "platform_lock_effect_verified": False,
        "publication_source_verified": False, "invoke_body_verified": False,
        "callback_effect_verified": False, "transitive_binding_closed": False,
        "scope": "selected-retain-local-increment-win64-v1",
        "object_sha256": hashlib.sha256(data["object"]).hexdigest(),
        "image_sha256": hashlib.sha256(data["image"]).hexdigest(),
        "report_sha256": hashlib.sha256(data["report"]).hexdigest(),
    }
    final = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())
    assert final["builder_retain_local"] == proof
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        receipt = temp / "current.receipt.json"
        receipt.write_bytes(create_receipt(data))
        assert verify_receipt(receipt.read_bytes(), data)["verified"] is True
        output = temp / "current.final.json"
        checked = finalizer(build, paths, output, receipt, retain=True)
        assert checked.returncode == 0 and output.exists(), checked.stderr
        assert json.loads(output.read_bytes())["builder_retain_local"] == proof

    refused("missing disassembly", lambda: verify_builder_retain_local(
        data["object"], data["image"], data["report"], {}), "disassembly")
    refused("bad report", lambda: verify_builder_retain_local(
        data["object"], data["image"], b"{}", codes), "raw compiler report")
    items = _instructions(codes[RETAIN], data["image"], RETAIN.lower())
    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    assert optimization in ("none", "O2")
    store = body_item(items, "89483c" if optimization == "none" else "8908")
    changed = paired_instruction(
        data["object"], data["image"], RETAIN, store,
        bytes.fromhex("89c990" if optimization == "none" else "89c9"))
    frozen, frozen_inputs, frozen_profile = fixed_inputs(build, data)
    refused("fixed builder record rejects changed object",
            lambda: verify_receipt(frozen, {**frozen_inputs, "object": changed[0]},
                                   profile=frozen_profile) if frozen_profile else
            verify_receipt(frozen, {**frozen_inputs, "object": changed[0]}),
            "object bytes differ")
    refused("reference increment has no writeback",
            lambda: verify_builder_retain_local(
                changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
            "increment")
    paired_finalizer_case(build, paths, *changed, "reference increment has no writeback")

    compare = body_item(items, "4539c8")
    changed = paired_instruction(data["object"], data["image"], RETAIN,
                                 compare, bytes.fromhex("4539c0"))
    refused("maximum self-compare", lambda: verify_builder_retain_local(
        changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
        "comparison")
    paired_finalizer_case(build, paths, *changed, "maximum self-compare")

    # Keep the comparison unchanged while clobbering its loaded input.
    # The selected body inventory must reject the write in that data path.
    maximum_reload = body_item(items, "448b44242c" if optimization == "none"
                               else "448b442428")
    changed = paired_instruction(data["object"], data["image"], RETAIN,
                                 maximum_reload, bytes.fromhex("4531c09090"))
    refused("maximum input zeroed before compare",
            lambda: verify_builder_retain_local(
                changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
            "maximum input")
    paired_finalizer_case(build, paths, *changed,
                          "maximum input zeroed before compare")

    closing = body_item(items, "448a4044")
    changed = paired_instruction(data["object"], data["image"], RETAIN,
                                 closing, bytes.fromhex("448a4045"))
    refused("wrong closing field", lambda: verify_builder_retain_local(
        changed[0], changed[1], data["report"], changed_codes(build, changed[1])),
        "closing")

    image = parse_image(data["image"])
    maximum_span = function_subject(data["object"], data["image"], image,
                                    0xbd60, MAXIMUM_BODY).ranges[0]
    constant = Instruction(image.preferred_base + maximum_span.rva,
                           bytes.fromhex("b8ffffffff"), "movl",
                           ("$0xffffffff", "%eax"))
    changed = paired_instruction(data["object"], data["image"], MAXIMUM_BODY,
                                 constant, bytes.fromhex("b8feffffff"))
    refused("numeric maximum changed", lambda: verify_builder_retain_local(
        changed[0], changed[1], data["report"], codes), "UINT32_MAX")
    paired_finalizer_case(build, paths, *changed, "numeric maximum changed")
    print(f"{optimization}: selected retain route and five actual paired mutations checked")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: builder_retain_local_cases.py BUILD_DIR")
    check(Path(sys.argv[1]).resolve())
