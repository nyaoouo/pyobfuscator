"""Actual selected archive first-use arm and paired COFF/PE refusal cases."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"),
                str(Path(__file__).resolve().parent)]

from builder_archive_decoder_linkage_cases import (  # noqa: E402
    SPIN, _changed_codes, _codes, _paired_call)
from builder_archive_publication_cases import _paired_field, refused  # noqa: E402
from builder_entry_state_cases import cache_path  # noqa: E402
from cff_archive_origin_contract import ROLES as ARCHIVE_ROLES  # noqa: E402
from cff_builder_archive_decoder_linkage import (  # noqa: E402
    ACQUIRE, ARCHIVE_DECODER_CALLEES, _branch_target, _recipes,
    verify_builder_archive_decoder_linkage)
from cff_builder_archive_first_use import (  # noqa: E402
    CAS, ERASE, LOAD, STORE, verify_builder_archive_first_use)
from cff_builder_original_predicates import _dispatcher_destination, _states  # noqa: E402
from cff_joint_machine_evidence import _instructions  # noqa: E402


def _stale_finalizer(build, objdump, changed_object, changed_image):
    # The original fixed receipt rejects changed object bytes before the
    # optional semantic proof. This is a separate output-lifecycle boundary.
    demo = build / "demo"
    with TemporaryDirectory(dir=build) as directory:
        scratch = Path(directory)
        object_path = scratch / "changed.obj"
        image_path = scratch / "changed.dll"
        output = scratch / "stale.json"
        object_path.write_bytes(changed_object)
        image_path.write_bytes(changed_image)
        output.write_bytes(b"stale")
        command = [
            sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
            str(objdump), str(image_path),
            str(demo / "payload.cff.coverage.json"), "--output", str(output),
            "--post-mixed-plan", str(demo / "payload.post-mixed.edges.json"),
            "--post-mixed-private", str(demo / "payload.binding.private.json"),
            "--post-mixed-material", str(demo / "release-material.private.json"),
            "--post-mixed-scoped", str(demo / "payload.scope-material.private.bin"),
            "--builder-receipt", str(build / "builder.fixed.json"),
            "--builder-input-ir", str(demo / "payload.archive.prepared.ll"),
            "--builder-object", str(object_path),
            "--builder-subjects", "--builder-entry-states",
            "--builder-archive-publication", "--builder-archive-decoder-linkage",
            "--builder-archive-first-use-arm",
        ]
        origin = json.loads((build / "archive.origin.json").read_bytes())
        child = json.loads((build / "builder.replay.json").read_bytes())
        command += [
            "--builder-replay-record", str(build / "builder.replay.json"),
            "--builder-transformed-ir", str(demo / "payload.cff.ll"),
            "--builder-request-manifest", str(demo / "payload.archive.requests.json"),
            "--builder-recipe", str(demo / "payload.binding.recipe.json"),
            "--builder-opt-exe", child["paths"]["opt_exe"],
            "--builder-clang-exe", child["paths"]["clang_exe"],
            "--builder-pass-plugin", child["paths"]["pass_plugin"],
            "--archive-origin-record", str(build / "archive.origin.json"),
        ]
        command += ["--archive-origin-role=" + role + "=" + origin["paths"][role]
                    for role in ARCHIVE_ROLES]
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, timeout=90)
        assert result.returncode != 0 and not output.exists(), result.stderr
        assert "builder receipt verification failed:" in result.stderr, result.stderr


def check(build):
    demo = build / "demo"
    object_bytes = (demo / "payload.cff.obj").read_bytes()
    image_path = demo / "libpyobf_native_demo_inner.dll"
    image_bytes = image_path.read_bytes()
    report_bytes = (demo / "payload.cff.coverage.json").read_bytes()
    objdump = cache_path(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    codes = _codes(objdump, image_path)

    def old(obj=object_bytes, image=image_bytes, disassembly=codes):
        return verify_builder_archive_decoder_linkage(obj, image, report_bytes,
                                                      disassembly)

    def prove(obj=object_bytes, image=image_bytes, disassembly=codes):
        return verify_builder_archive_first_use(obj, image, report_bytes,
                                                disassembly)

    proof = prove()
    expected = {
        "verified": True,
        "conditional_first_use_arm_verified": True,
        "state_zero_cas_route_verified": True,
        "decode_result_route_verified": True,
        "failure_erase_route_verified": True,
        "state_publish_route_verified": True,
        "normal_first_use_reachability_verified": False,
        "decoder_effect_verified": False,
        "cache_effect_verified": False,
        "platform_crypto_verified": False,
        "cache_content_integrity_verified": False,
        "external_destination_integrity_verified": False,
        "transitive_archive_effect_closed": False,
        "scope": "selected-archive-conditional-first-use-arm-win64-v1",
        "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
    assert proof == expected
    final = json.loads((demo / "payload.cff.final.json").read_bytes())
    assert final["builder_archive_first_use_arm"] == proof

    with TemporaryDirectory(dir=build) as directory:
        scratch = Path(directory)
        items = _instructions(codes[ACQUIRE], image_bytes, ACQUIRE.lower())
        for label, callee in (("load", LOAD), ("CAS", CAS),
                              ("erase", ERASE), ("publish", STORE)):
            matches = [item for item in items if item.opcode in ("call", "callq")
                       and item.operands and callee.lower() in item.operands[0]]
            assert len(matches) == 1
            changed_object, changed_image = _paired_call(
                object_bytes, image_bytes, matches[0], SPIN,
                caller_name=ACQUIRE)
            changed_codes = _changed_codes(objdump, scratch, changed_image)
            assert old(changed_object, changed_image, changed_codes)["verified"] is True
            refused(f"paired {label} retarget", lambda obj=changed_object,
                    image=changed_image, disassembly=changed_codes:
                    prove(obj, image, disassembly), "call misses its exact PE target")
            if label == "CAS":
                _stale_finalizer(build, objdump, changed_object, changed_image)

        compare = next(item for item in items if item.raw == b"\x41\x83\xf8\x00" and
                       item.address > next(item.address for item in items
                                           if item.opcode in ("call", "callq") and
                                           CAS.lower() in item.operands[0]))
        changed_object, changed_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, compare, 3, b"\x01")
        changed_codes = _changed_codes(objdump, scratch, changed_image)
        assert old(changed_object, changed_image, changed_codes)["verified"] is True
        refused("paired CAS result comparison", lambda: prove(
            changed_object, changed_image, changed_codes),
            "conditional source comparison differs")

        dispatcher = _branch_target(items[13], {item.address for item in items})
        zero_state = _states(ACQUIRE, _recipes(report_bytes)[ACQUIRE])[20]
        zero_body = _dispatcher_destination(items, dispatcher, zero_state, 0xbc)
        zero_compare = next(item for item in items if
                            zero_body <= item.address < zero_body + 0x40 and
                            item.opcode == "cmpl" and
                            item.operands == ("$0x0", "%r8d"))
        assert zero_compare.raw == b"\x41\x83\xf8\x00"
        wrong_zero_object, wrong_zero_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, zero_compare, 3, b"\x01")
        wrong_zero_codes = _changed_codes(objdump, scratch, wrong_zero_image)
        assert old(wrong_zero_object, wrong_zero_image, wrong_zero_codes)["verified"] is True
        refused("paired state-zero comparison", lambda: prove(
            wrong_zero_object, wrong_zero_image, wrong_zero_codes),
            "conditional source comparison differs")

        publish_call = next(item for item in items if item.opcode in ("call", "callq")
                            and STORE.lower() in item.operands[0])
        state_read = items[items.index(publish_call) - 3]
        assert state_read.raw == b"\x8b\x94\x24\xa0\x00\x00\x00"
        wrong_state_object, wrong_state_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, state_read, 3, b"\x9c")
        wrong_state_codes = _changed_codes(objdump, scratch, wrong_state_image)
        assert old(wrong_state_object, wrong_state_image, wrong_state_codes)["verified"] is True
        refused("paired publication state source", lambda: prove(
            wrong_state_object, wrong_state_image, wrong_state_codes),
            "state publication and return status")

        missing = dict(codes)
        missing.pop(ARCHIVE_DECODER_CALLEES[-1])
        refused("missing decoder code", lambda: prove(disassembly=missing),
                "five-symbol disassembly")
        refused("unsupported compiler report", lambda: verify_builder_archive_first_use(
            object_bytes, image_bytes, b"{}", codes), "function rows")

    print("archive first-use arm: actual final report, paired old-admit/new-refuse and stale-output pass")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
