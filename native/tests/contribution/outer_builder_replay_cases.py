"""Check frozen outer compiler outputs and final PE against actual artifacts."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"),
                str(Path(__file__).resolve().parent)]

from cff_builder_receipt import (  # noqa: E402
    OUTER_REPLAY_PROFILE, OUTER_REPLAY_ROLES, verify_receipt,
)
from cff_outer_builder_replay import (  # noqa: E402
    RECORD_SCOPE, freeze, verify_outer_replay_record,
)
import cff_outer_builder_replay as outer_replay  # noqa: E402
from coff_layout import parse_object  # noqa: E402
from function_inventory import create as create_inventory  # noqa: E402
from function_subject import function_subject  # noqa: E402
from parent_callback_cases import DISPATCH, cache, post_finalize  # noqa: E402
from pe_layout import parse_image, rva_section  # noqa: E402


def refused(label, action, fragment):
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), f"{label}: wrong refusal: {error}"
        return
    raise AssertionError(f"{label}: altered input was accepted")


def paths_for(build, target):
    demo = build / "demo"
    prefix = demo / target
    source_opt = cache(build, "PYOBF_NATIVE_OUTER_CFF_SOURCE_OPT")
    assert source_opt in ("none", "O2")
    input_ir = prefix.with_suffix(".optimized.ll" if source_opt == "O2" else ".requested.ll")
    roles = {
        "image": demo / f"lib{target}.dll",
        "report": prefix.with_suffix(".coverage.json"),
        "combined_ir": prefix.with_suffix(".combined.ll"),
        "requested_ir": prefix.with_suffix(".requested.ll"),
        "request_manifest": prefix.with_suffix(".requests.json"),
        "input_ir": input_ir,
        "transformed_ir": prefix.with_suffix(".cff.ll"),
        "object": prefix.with_suffix(".obj"),
        "inventory": demo / f"{target}.obj.ownership.json",
        "unfinalized_image": demo / "unfinalized" / f"lib{target}.dll",
        "release_report": prefix.with_suffix(".release.json"),
        "recipe": Path(cache(build, "PYOBF_NATIVE_OUTER_CFF_CONFIG")),
        "opt_exe": Path(cache(build, "PYOBF_NATIVE_OPT_EXECUTABLE")),
        "clang_exe": Path(cache(build, "CMAKE_CXX_COMPILER")),
        "pass_plugin": build / "llvm" / "pyobf_native_cff.dll",
        "owner_plan": demo / f"{target}_unfinalized.reference-plan.private.json",
        "release_plan": demo / "release-plan.private.json",
        "private": demo / "payload.binding.private.json",
        "scoped": demo / "payload.scope-material.private.bin",
        "child_final": demo / "payload.cff.final.json",
        "child_image": demo / "libpyobf_native_demo_inner.dll",
        "release_material": demo / "release-material.private.json",
        "mixed_plan": demo / "payload.post-mixed.edges.json",
    }
    assert set(roles) == set(OUTER_REPLAY_ROLES) - {"replay_record"}
    frozen = Path(cache(build, "PYOBF_NATIVE_DEMO_OUTER_BUILDER_DIR"))
    return roles, frozen / f"{target}.replay.json", frozen / f"{target}.receipt.json"


def _call_finalizer(build, roles, record, receipt, output, *, outer):
    demo = build / "demo"
    command = [
        sys.executable, str(ROOT / "demo" / "check_linked_cff.py"),
        cache(build, "PYOBF_NATIVE_OBJDUMP_EXECUTABLE"),
        str(roles["image"]), str(roles["report"]), "--output", str(output),
        "--owner-object", str(roles["object"]),
        "--owner-inventory", str(roles["inventory"]),
        "--owner-plan", str(roles["owner_plan"]),
        "--post-release-report", str(roles["release_report"]),
        "--post-release-plan", str(roles["release_plan"]),
        "--post-child-image", str(roles["child_image"]),
        "--post-child-final", str(roles["child_final"]),
        "--post-child-raw", str(demo / "payload.cff.coverage.json"),
        "--post-private", str(roles["private"]),
        "--post-scoped", str(roles["scoped"]),
        "--post-join-mixed-plan", str(roles["mixed_plan"]),
        "--post-join-material", str(roles["release_material"]),
        "--parent-callback",
    ]
    if outer:
        command.extend(("--outer-builder-receipt", str(receipt),
                        "--outer-builder-record", str(record)))
        command.extend("--outer-builder-role=" + role + "=" + str(path)
                       for role, path in roles.items())
    return subprocess.run(command, capture_output=True, text=True,
                          check=False, timeout=60)


def _changed_dispatch(object_bytes, raw_bytes, final_bytes):
    obj, image = parse_object(object_bytes), parse_image(final_bytes)
    roots = [symbol for symbol in obj.symbols if symbol.name == DISPATCH and
             symbol.type == 0x20 and symbol.section > 0 and symbol.value == 0]
    assert len(roots) == 1
    section = obj.sections[roots[0].section - 1]
    subject = function_subject(object_bytes, final_bytes, image, 0xd310, DISPATCH)
    assert len(subject.ranges) == 1 and subject.ranges[0].size == section.size
    span = subject.ranges[0]
    original = object_bytes[section.offset:section.offset + section.size]
    candidates = [offset for offset, byte in enumerate(original) if byte == 0xcc and
                  all(not (relocation.offset <= offset < relocation.offset + 4)
                      for relocation in section.relocations)]
    assert candidates, "the actual linked dispatch has no nonrelocated int3"
    offset = candidates[-1]
    section_image = rva_section(image, span.rva + offset, 1, logical=True)
    raw_offset = section_image.raw_offset + span.rva + offset - section_image.rva
    assert raw_bytes[raw_offset] == 0xcc and final_bytes[raw_offset] == 0xcc
    changed_object, changed_raw = bytearray(object_bytes), bytearray(raw_bytes)
    changed_object[section.offset + offset] = 0x90
    changed_raw[raw_offset] = 0x90
    return bytes(changed_object), bytes(changed_raw)


def _fixed_pe_red(build, roles, record, receipt):
    demo = build / "demo"
    with TemporaryDirectory(dir=build) as temporary:
        scratch = Path(temporary)
        changed_object, changed_raw = _changed_dispatch(
            roles["object"].read_bytes(), roles["unfinalized_image"].read_bytes(),
            roles["image"].read_bytes())
        changed = dict(roles)
        changed["object"] = scratch / "outer.obj"
        changed["inventory"] = scratch / "outer.obj.ownership.json"
        changed["unfinalized_image"] = scratch / "outer.raw.dll"
        changed["image"] = scratch / "outer.final.dll"
        changed["release_report"] = scratch / "outer.release.json"
        changed["object"].write_bytes(changed_object)
        changed["inventory"].write_bytes(create_inventory(
            changed_object, roles["transformed_ir"].read_bytes(),
            roles["report"].read_bytes()))
        changed["unfinalized_image"].write_bytes(changed_raw)
        post_finalize(build, changed["unfinalized_image"], changed["image"],
                      changed["release_report"])
        old = _call_finalizer(build, changed, record, receipt,
                              scratch / "old.final.json", outer=False)
        assert old.returncode == 0, old.stderr
        output = scratch / "stale.final.json"
        output.write_bytes(b"stale")
        new = _call_finalizer(build, changed, record, receipt, output, outer=True)
        assert new.returncode != 0 and not output.exists(), new.stderr
        assert ("outer builder consistency failed: builder receipt: image bytes differ" in
                new.stderr and "parent callback proof failed" not in new.stderr), new.stderr
    print("outer fixed PE: re-finalized paired COFF/PE old-admitted, new-refused")


def _fixed_report_red(build, roles, record, receipt):
    with TemporaryDirectory(dir=build) as temporary:
        scratch = Path(temporary)
        changed = dict(roles)
        changed["report"] = scratch / "outer.coverage.json"
        changed["inventory"] = scratch / "outer.obj.ownership.json"
        report = json.loads(roles["report"].read_bytes())
        report["outer_builder_probe"] = True
        changed["report"].write_bytes((json.dumps(report, sort_keys=True,
                                                   separators=(",", ":")) + "\n").encode())
        changed["inventory"].write_bytes(create_inventory(
            roles["object"].read_bytes(), roles["transformed_ir"].read_bytes(),
            changed["report"].read_bytes()))
        old = _call_finalizer(build, changed, record, receipt,
                              scratch / "old.final.json", outer=False)
        assert old.returncode == 0, old.stderr
        output = scratch / "stale.final.json"
        output.write_bytes(b"stale")
        new = _call_finalizer(build, changed, record, receipt, output, outer=True)
        assert new.returncode != 0 and not output.exists(), new.stderr
        assert "outer builder consistency failed: builder receipt: report bytes differ" in new.stderr
    print("outer fixed report: paired report/inventory old-admitted, new-refused")


def _paired_private_refusal(build, roles, record, receipt):
    with TemporaryDirectory(dir=build) as temporary:
        scratch = Path(temporary)
        changed = dict(roles)
        changed["private"] = scratch / "private.json"
        changed["child_final"] = scratch / "child.final.json"
        old_private = roles["private"].read_bytes()
        new_private = old_private + b" "
        changed["private"].write_bytes(new_private)
        old_digest = hashlib.sha256(old_private).hexdigest().encode()
        new_digest = hashlib.sha256(new_private).hexdigest().encode()
        old_child_final = roles["child_final"].read_bytes()
        assert old_child_final.count(old_digest) == 2
        changed["child_final"].write_bytes(old_child_final.replace(old_digest, new_digest))
        old = _call_finalizer(build, changed, record, receipt,
                              scratch / "old.final.json", outer=False)
        assert old.returncode != 0 and "private release plan belongs" in old.stderr
        output = scratch / "stale.final.json"
        output.write_bytes(b"stale")
        new = _call_finalizer(build, changed, record, receipt, output, outer=True)
        assert new.returncode != 0 and not output.exists(), new.stderr
        assert "outer builder consistency failed: builder receipt: private bytes differ" in new.stderr
    print("outer private/child pair: existing release plan and fixed receipt both refuse")


def _snapshot_swap(build, roles, options, stage_inputs, record=None, receipt=None):
    """A transient original-path change must not enter any replay stage."""
    original_run = outer_replay._run

    def swapped_run(command, cwd, name):
        saved = []
        try:
            for role in stage_inputs.get(name, ()):
                path = roles[role]
                data, stat = path.read_bytes(), path.stat()
                saved.append((path, data, stat))
                path.write_bytes(b"invalid transient compiler input\n")
            return original_run(command, cwd, name)
        finally:
            for path, data, stat in saved:
                path.write_bytes(data)
                os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))

    with TemporaryDirectory(dir=build) as temporary:
        scratch = Path(temporary)
        outputs = {**roles, "record": scratch / "record.json",
                   "receipt": scratch / "receipt.json"}
        with patch.object(outer_replay, "_run", side_effect=swapped_run):
            freeze(outputs, options["opt_options"], options["clang_options"],
                   options["source_opt"])
        frozen_record = outputs["record"].read_bytes()
        frozen_receipt = outputs["receipt"].read_bytes()
        exact = {role: path.read_bytes() for role, path in roles.items()}
        exact["replay_record"] = frozen_record
        assert verify_outer_replay_record(frozen_record, exact)["verified"]
        assert verify_receipt(frozen_receipt, exact,
                              profile=OUTER_REPLAY_PROFILE)["verified"]
        if record is not None:
            assert frozen_record == record.read_bytes()
            assert frozen_receipt == receipt.read_bytes()
    print("outer transient original-path swaps: frozen replay remains exact")


def _source_o2_snapshot_swap(build, roles, options):
    with TemporaryDirectory(dir=build) as temporary:
        scratch = Path(temporary)
        o2 = dict(roles)
        o2["input_ir"] = scratch / "source.optimized.ll"
        o2["transformed_ir"] = scratch / "source.cff.ll"
        o2["report"] = scratch / "source.coverage.json"
        o2["object"] = scratch / "source.obj"
        o2["inventory"] = scratch / "source.ownership.json"
        opt = roles["opt_exe"].as_posix()
        plugin = roles["pass_plugin"].as_posix()
        cwd = roles["combined_ir"].parent
        outer_replay._run([opt, "-passes=default<O2>", "-verify-each", "-S",
                           roles["requested_ir"].as_posix(), "-o",
                           o2["input_ir"].as_posix()],
                          cwd, "source O2 fixture")
        outer_replay._run([opt, "-load-pass-plugin", plugin,
                           "-passes=pyobf-native-cff", *options["opt_options"],
                           "-pyobf-cff-requests-input=" + roles["request_manifest"].as_posix(),
                           "-pyobf-cff-report=" + o2["report"].as_posix(),
                           "-verify-each", "-S", o2["input_ir"].as_posix(),
                           "-o", o2["transformed_ir"].as_posix()], cwd, "CFF O2 fixture")
        outer_replay._run([roles["clang_exe"].as_posix(), *options["clang_options"],
                           "-c", o2["transformed_ir"].as_posix(), "-o",
                           o2["object"].as_posix()],
                          cwd, "Clang O2 fixture")
        o2["inventory"].write_bytes(create_inventory(
            o2["object"].read_bytes(), o2["transformed_ir"].read_bytes(),
            o2["report"].read_bytes()))
        _snapshot_swap(build, o2, {**options, "source_opt": "O2"},
                       {"source O2": ("requested_ir",)})


def check(build):
    assert cache(build, "PYOBF_NATIVE_DEMO_G3_OUTER_REPLAY") == "ON"
    for target in ("pyobf_native_demo_outer",
                   "pyobf_native_demo_outer_triggered"):
        roles, record, receipt = paths_for(build, target)
        inputs = {role: path.read_bytes() for role, path in roles.items()}
        inputs["replay_record"] = record.read_bytes()
        verified = verify_receipt(receipt.read_bytes(), inputs,
                                  profile=OUTER_REPLAY_PROFILE)
        assert verified["verified"] is True
        proof = verify_outer_replay_record(record.read_bytes(), inputs)
        assert proof["verified"] is True and proof["scope"] == RECORD_SCOPE
        final = json.loads((build / "demo" / f"{target}.final.json").read_bytes())
        assert final["outer_builder_consistency"] == proof
        assert final["image_sha256"] == verified["inputs"]["image"]
        changed = dict(inputs, report=inputs["report"] + b" ")
        refused("changed raw report", lambda: verify_outer_replay_record(
            record.read_bytes(), changed), "report differs")
        refused("changed fixed receipt", lambda: verify_receipt(
            receipt.read_bytes(), changed, profile=OUTER_REPLAY_PROFILE),
            "report bytes differ")
        parsed = json.loads(record.read_bytes())
        parsed["profile"] = "wrong-profile"
        wrong = (json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n").encode()
        refused("wrong replay profile", lambda: verify_outer_replay_record(
            wrong, dict(inputs, replay_record=wrong)), "record shape differs")
        duplicate = record.read_bytes().replace(b'{"clang_options":',
                                                 b'{"clang_options":[],"clang_options":', 1)
        refused("duplicate record key", lambda: verify_outer_replay_record(
            duplicate, dict(inputs, replay_record=duplicate)), "duplicate record key")
        with TemporaryDirectory(dir=build) as temporary:
            scratch = Path(temporary)
            output_record = scratch / "record.json"
            output_receipt = scratch / "receipt.json"
            output_record.write_bytes(b"stale")
            output_receipt.write_bytes(b"stale")
            options = json.loads(record.read_bytes())
            refused("bad opt options", lambda: freeze(
                {**roles, "record": output_record, "receipt": output_receipt},
                ["-pyobf-cff-config=wrong"], options["clang_options"],
                options["source_opt"]), "closed outer CFF selection")
            assert not output_record.exists() and not output_receipt.exists()
            refused("output aliases object", lambda: freeze(
                {**roles, "record": roles["object"], "receipt": output_receipt},
                options["opt_options"], options["clang_options"],
                options["source_opt"]), "aliases an input")
            refused("relative compiler path", lambda: freeze(
                {**roles, "opt_exe": Path(roles["opt_exe"].name),
                 "record": output_record, "receipt": output_receipt},
                options["opt_options"], options["clang_options"],
                options["source_opt"]), "input paths must be absolute")
            assert not output_record.exists() and not output_receipt.exists()
            if target == "pyobf_native_demo_outer":
                altered_object = scratch / "altered.obj"
                object_bytes = bytearray(roles["object"].read_bytes())
                object_bytes[-1] ^= 1
                altered_object.write_bytes(object_bytes)
                output_record.write_bytes(b"stale")
                output_receipt.write_bytes(b"stale")
                refused("replayed object mismatch", lambda: freeze(
                    {**roles, "object": altered_object,
                     "record": output_record, "receipt": output_receipt},
                    options["opt_options"], options["clang_options"],
                    options["source_opt"]),
                    "object differs from deterministic compiler replay")
                assert not output_record.exists() and not output_receipt.exists()
        print(f"outer replay {target}: exact record/receipt and negative inputs passed")
        if target == "pyobf_native_demo_outer":
            _snapshot_swap(build, roles, options, {
                "request opt": ("combined_ir",),
                "CFF opt": ("input_ir", "request_manifest"),
                "Clang": ("transformed_ir",),
            }, record, receipt)
            if cache(build, "PYOBF_NATIVE_DEMO_ARCHIVE") == "ON":
                _source_o2_snapshot_swap(build, roles, options)
            _fixed_pe_red(build, roles, record, receipt)
            _fixed_report_red(build, roles, record, receipt)
            _paired_private_refusal(build, roles, record, receipt)


if __name__ == "__main__":
    assert len(sys.argv) == 2
    check(Path(sys.argv[1]).resolve())
