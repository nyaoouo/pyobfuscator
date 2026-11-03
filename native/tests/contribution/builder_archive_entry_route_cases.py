"""Actual selected archive entry route and paired predecessor-admitted refusals."""

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
    ACQUIRE, PARSE, _items, _subjects, verify_builder_archive_decoder_linkage)
from cff_builder_archive_entry_route import (  # noqa: E402
    ACCESS, OVERLAPS, SCOPE, verify_builder_archive_entry_route)
from cff_builder_archive_first_use import verify_builder_archive_first_use  # noqa: E402
from pe_layout import parse_image  # noqa: E402


def _stale_finalizer(build, objdump, changed_object, changed_image):
    # The frozen receipt refuses the changed object before this optional
    # semantic gate. Output clearing is an independent finalizer obligation.
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
            "--builder-archive-first-use-arm", "--builder-archive-entry-route",
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
        assert result.returncode != 0, "changed object unexpectedly passed finalization"
        assert "builder receipt verification failed:" in result.stderr, result.stderr
        assert not output.exists(), "finalizer retained stale output after refusal"


def check(build):
    demo = build / "demo"
    object_bytes = (demo / "payload.cff.obj").read_bytes()
    image_path = demo / "libpyobf_native_demo_inner.dll"
    image_bytes = image_path.read_bytes()
    report_bytes = (demo / "payload.cff.coverage.json").read_bytes()
    objdump = cache_path(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE")
    codes = _codes(objdump, image_path)

    def predecessors(obj=object_bytes, image=image_bytes, disassembly=codes):
        decoder = verify_builder_archive_decoder_linkage(
            obj, image, report_bytes, disassembly)
        first_use = verify_builder_archive_first_use(
            obj, image, report_bytes, disassembly)
        assert decoder["verified"] is first_use["verified"] is True
        return decoder, first_use

    def prove(obj=object_bytes, image=image_bytes, disassembly=codes,
              predecessor_proofs=None):
        decoder, first_use = predecessor_proofs or predecessors(
            obj, image, disassembly)
        return verify_builder_archive_entry_route(
            obj, image, report_bytes, disassembly, decoder, first_use)

    original_predecessors = predecessors()
    proof = prove(predecessor_proofs=original_predecessors)
    expected = {
        "verified": True,
        "selected_success_path_to_first_use_verified": True,
        "parse_guard_route_verified": True,
        "storage_guard_route_verified": True,
        "access_guard_route_verified": True,
        "first_use_join_verified": True,
        "parse_effect_verified": False,
        "overlap_effect_verified": False,
        "access_effect_verified": False,
        "platform_atomic_effect_verified": False,
        "cache_effect_verified": False,
        "all_runtime_inputs_reach_arm_verified": False,
        "transitive_archive_effect_closed": False,
        "scope": SCOPE,
        "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
    assert proof == expected
    final = json.loads((demo / "payload.cff.final.json").read_bytes())
    assert final["builder_archive_entry_route"] == proof

    image = parse_image(image_bytes)
    items = _items(codes[ACQUIRE], image_bytes, image, ACQUIRE,
                   _subjects(object_bytes, image_bytes, image)[ACQUIRE])
    with TemporaryDirectory(dir=build) as directory:
        scratch = Path(directory)

        # Changing only the selector keeps both predecessor machine proofs
        # valid while reversing the parse-success route into the storage guards.
        parse_call = next(item for item in items if item.opcode in ("call", "callq")
                          and item.operands and PARSE.lower() in item.operands[0])
        parse_selector = next(item for item in items if item.raw == b"\x0f\x44\xca" and
                              0 < item.address - parse_call.address < 0x40)
        parse_mut_object, parse_mut_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, parse_selector, 1, b"\x45")
        parse_codes = _changed_codes(objdump, scratch, parse_mut_image)
        parse_predecessors = predecessors(parse_mut_object, parse_mut_image,
                                          parse_codes)
        refused("paired parse-success selector", lambda: prove(
            parse_mut_object, parse_mut_image, parse_codes, parse_predecessors),
            "selector polarity differs")
        _stale_finalizer(build, objdump, parse_mut_object, parse_mut_image)

        access_call = next(item for item in items if item.opcode in ("call", "callq")
                           and item.operands and ACCESS.lower() in item.operands[0])
        access_selector = next(item for item in items if item.address > access_call.address
                               and item.raw == b"\x0f\x45\xca" and
                               item.address - access_call.address < 0x30)
        access_object, access_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, access_selector, 1, b"\x44")
        access_codes = _changed_codes(objdump, scratch, access_image)
        access_predecessors = predecessors(access_object, access_image, access_codes)
        refused("paired access-success selector", lambda: prove(
            access_object, access_image, access_codes, access_predecessors),
            "selector polarity differs")

        key_source = next(item for item in items if item.opcode == "movq" and
                          item.operands == ("0x50(%rsp)", "%r8"))
        key_guard = next(item for item in items if item.opcode == "cmpq" and
                         item.operands == ("$0x0", "%r8") and
                         0 < item.address - key_source.address < 0x30)
        wrong_key_object, wrong_key_image = _paired_field(
            object_bytes, image_bytes, ACQUIRE, key_guard, 3, b"\x01")
        wrong_key_codes = _changed_codes(objdump, scratch, wrong_key_image)
        key_predecessors = predecessors(wrong_key_object, wrong_key_image,
                                        wrong_key_codes)
        refused("paired key guard", lambda: prove(
            wrong_key_object, wrong_key_image, wrong_key_codes, key_predecessors),
            "conditional source comparison differs")

        package_call = next(item for item in items if item.opcode in ("call", "callq")
                            and item.operands and OVERLAPS.lower() in item.operands[0]
                            and items[items.index(item) - 1].operands ==
                            ("0xa8(%rsp)", "%rdx"))
        redirected_object, redirected_image = _paired_call(
            object_bytes, image_bytes, package_call, SPIN, caller_name=ACQUIRE)
        redirected_codes = _changed_codes(objdump, scratch, redirected_image)
        redirected_predecessors = predecessors(
            redirected_object, redirected_image, redirected_codes)
        refused("paired package-overlap retarget", lambda: prove(
            redirected_object, redirected_image, redirected_codes,
            redirected_predecessors), "call misses its exact PE target")

        refused("missing selected code", lambda: prove(disassembly={}),
                "disassembly")
        refused("stale predecessor proof", lambda: verify_builder_archive_entry_route(
            object_bytes, image_bytes, report_bytes, codes,
            {**original_predecessors[0], "image_sha256": "0" * 64},
            original_predecessors[1]),
            "decoder predecessor proof")

        broken_object, broken_image = _paired_call(
            object_bytes, image_bytes, parse_call, SPIN, caller_name=ACQUIRE)
        broken_codes = _changed_codes(objdump, scratch, broken_image)
        forged_hashes = {
            "object_sha256": hashlib.sha256(broken_object).hexdigest(),
            "image_sha256": hashlib.sha256(broken_image).hexdigest(),
        }
        refused("forged predecessor dictionaries over broken decoder", lambda:
                verify_builder_archive_entry_route(
                    broken_object, broken_image, report_bytes, broken_codes,
                    {**original_predecessors[0], **forged_hashes},
                    {**original_predecessors[1], **forged_hashes}),
                "missing unique linked call")

    print("archive entry route: actual final report, paired old-admit/new-refuse and stale-output pass")


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
