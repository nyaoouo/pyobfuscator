"""Exercise the selected invoke route against actual linked Win64 artifacts."""

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
from cff_builder_bound_call import BOUND_CALL, INVOKE, verify_builder_bound_call  # noqa: E402
from cff_builder_invoke_local import verify_builder_invoke_local  # noqa: E402
from cff_builder_receipt import create_receipt, verify_receipt  # noqa: E402
from cff_joint_machine_evidence import _instructions  # noqa: E402


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), (label, error)
        return
    raise AssertionError(f"{label}: changed input was accepted")


def finalizer(build, paths, output, receipt, *, invoke):
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
               "--builder-context-availability-effect", "--builder-bound-call",
               "--builder-retain-local"]
    if invoke:
        command.append("--builder-invoke-local")
    return subprocess.run(command, capture_output=True, text=True, timeout=90,
                          check=False)


def changed_codes(build, image_bytes, names):
    with TemporaryDirectory(dir=build) as directory:
        path = Path(directory) / "paired.dll"
        path.write_bytes(image_bytes)
        objdump = cache_value(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
        return {name: disassembly(objdump, path, name) for name in names}


def paired_finalizer_case(build, paths, changed_object, changed_image, label):
    """A fresh paired receipt isolates this local gate from the fixed record."""
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        changed = {**paths, "object": temp / "paired.obj", "image": temp / "paired.dll"}
        changed["object"].write_bytes(changed_object)
        changed["image"].write_bytes(changed_image)
        data = {role: path.read_bytes() for role, path in changed.items()}
        receipt = temp / "paired.receipt.json"
        receipt.write_bytes(create_receipt(data))
        assert verify_receipt(receipt.read_bytes(), data)["verified"] is True
        predecessor = finalizer(build, changed, temp / "predecessor.json", receipt,
                                invoke=False)
        assert predecessor.returncode == 0 and (temp / "predecessor.json").exists(), \
            (label, predecessor.stderr)
        output = temp / "stale.json"
        output.write_bytes(b"stale")
        current = finalizer(build, changed, output, receipt, invoke=True)
        assert current.returncode != 0 and not output.exists(), (label, current.stderr)
        assert ("builder invoke local route proof failed:" in current.stderr and
                "builder receipt verification failed:" not in current.stderr), \
            (label, current.stderr)
    print(f"{label}: predecessor admits; invoke gate refuses and clears stale output")


def check(build):
    paths = inputs_for(build)
    data = {role: path.read_bytes() for role, path in paths.items()}
    optimization = cache_value(build, "PYOBF_NATIVE_CFF_SOURCE_OPT")
    assert optimization in ("none", "O2")
    codes = changed_codes(build, data["image"], (INVOKE,))
    proof = verify_builder_invoke_local(data["object"], data["image"],
                                        data["report"], codes)
    assert proof == {
        "verified": True, "request_guard_route_verified": True,
        "admit_status_route_verified": True,
        "callback_argument_route_verified": True,
        "callback_call_route_verified": True,
        "complete_call_route_verified": True,
        "result_return_route_verified": True,
        "admit_effect_verified": False,
        "complete_effect_verified": False,
        "callback_identity_verified": False,
        "callback_effect_verified": False,
        "platform_lock_effect_verified": False,
        "runtime_memory_integrity_verified": False,
        "transitive_binding_closed": False,
        "scope": "selected-invoke-local-route-win64-v1",
        "object_sha256": hashlib.sha256(data["object"]).hexdigest(),
        "image_sha256": hashlib.sha256(data["image"]).hexdigest(),
        "report_sha256": hashlib.sha256(data["report"]).hexdigest(),
    }
    final = json.loads((build / "demo" / "payload.cff.final.json").read_bytes())
    assert final["builder_invoke_local"] == proof
    with TemporaryDirectory(dir=build) as directory:
        temp = Path(directory)
        receipt = temp / "current.receipt.json"
        receipt.write_bytes(create_receipt(data))
        output = temp / "current.final.json"
        checked = finalizer(build, paths, output, receipt, invoke=True)
        assert checked.returncode == 0 and output.exists(), checked.stderr
        assert json.loads(output.read_bytes())["builder_invoke_local"] == proof
    refused("missing disassembly", lambda: verify_builder_invoke_local(
        data["object"], data["image"], data["report"], {}), "disassembly")
    refused("bad report", lambda: verify_builder_invoke_local(
        data["object"], data["image"], b"{}", codes), "raw compiler report")

    items = _instructions(codes[INVOKE], data["image"], INVOKE.lower())
    callback = body_item(items, "ffd0")
    changed = paired_instruction(data["object"], data["image"], INVOKE,
                                 callback, bytes.fromhex("9090"))
    predecessor_codes = changed_codes(build, changed[1], (BOUND_CALL,))
    assert verify_builder_bound_call(changed[0], changed[1], data["report"],
                                     predecessor_codes)["verified"] is True
    refused("callback removed", lambda: verify_builder_invoke_local(
        changed[0], changed[1], data["report"],
        changed_codes(build, changed[1], (INVOKE,))), "call")
    frozen, frozen_inputs, frozen_profile = fixed_inputs(build, data)
    refused("fixed receipt rejects changed object", lambda: verify_receipt(
        frozen, {**frozen_inputs, "object": changed[0]},
        profile=frozen_profile) if frozen_profile else verify_receipt(
            frozen, {**frozen_inputs, "object": changed[0]}), "object bytes differ")
    paired_finalizer_case(build, paths, *changed, "callback removed")

    request = body_item(items, "488b542460" if optimization == "none"
                        else "488b542428")
    changed = paired_instruction(data["object"], data["image"], INVOKE,
                                 request, bytes.fromhex("488b542468" if optimization == "none"
                                                        else "488b542448"))
    refused("callback request aliases context", lambda: verify_builder_invoke_local(
        changed[0], changed[1], data["report"],
        changed_codes(build, changed[1], (INVOKE,))), "callback")

    captured = body_item(items, "4889442468" if optimization == "none"
                         else "4889442448")
    changed = paired_instruction(data["object"], data["image"], INVOKE,
                                 captured, bytes.fromhex("4889442460" if optimization == "none"
                                                         else "4889442428"))
    refused("captured context overwrites request slot", lambda: verify_builder_invoke_local(
        changed[0], changed[1], data["report"],
        changed_codes(build, changed[1], (INVOKE,))), "context")

    if optimization == "none":
        size = body_item(items, "4981f800000100")
        changed = paired_instruction(data["object"], data["image"], INVOKE,
                                     size, bytes.fromhex("4981f800000200"))
        refused("larger request bypasses guard", lambda: verify_builder_invoke_local(
            changed[0], changed[1], data["report"],
            changed_codes(build, changed[1], (INVOKE,))), "comparison")
    else:
        slot = items[items.index(callback) - 4]
        assert slot.raw == bytes.fromhex("488b442448")
        changed = paired_instruction(data["object"], data["image"], INVOKE,
                                     slot, bytes.fromhex("488b442428"))
        refused("captured context aliases request", lambda: verify_builder_invoke_local(
            changed[0], changed[1], data["report"],
            changed_codes(build, changed[1], (INVOKE,))), "callback")
    print(f"{optimization}: invoke local actual route and paired bypasses checked")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: builder_invoke_local_cases.py BUILD_DIR")
    check(Path(sys.argv[1]).resolve())
