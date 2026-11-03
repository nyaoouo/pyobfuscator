"""Actual O2/archive wrapper route and selected original-predicate refusals."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT / "tools"), str(Path(__file__).resolve().parent)]

from builder_archive_publication_cases import _bytes, _code, _paired_field  # noqa: E402
from builder_replay_cases import finalizer, paths_for  # noqa: E402
from cff_builder_archive_publication import verify_builder_archive_publication  # noqa: E402
from cff_builder_o2_original_predicates import verify_builder_o2_original_predicates  # noqa: E402
from cff_builder_o2_predecessor import verify_o2_predecessor_record  # noqa: E402
from cff_builder_receipt import REPLAY_PROFILE, REPLAY_ROLES, verify_receipt  # noqa: E402
from cff_builder_original_predicates import _ir_function  # noqa: E402
from cff_joint_machine_evidence import _instructions  # noqa: E402
from payload_binding import WRAPPER  # noqa: E402


def refused(label, call, fragment):
    try:
        call()
    except ValueError as error:
        assert fragment in str(error), f"{label}: unexpected error: {error}"
        return
    raise AssertionError(f"{label}: altered input was admitted")


def check(build):
    demo, archive_record, archive_paths, archive_roles, names, objdump, codes, wrappers = _bytes(build)
    object_bytes = (demo / "payload.cff.obj").read_bytes()
    image_bytes = (demo / "libpyobf_native_demo_inner.dll").read_bytes()
    report = (demo / "payload.cff.coverage.json").read_bytes()
    edges = (demo / "payload.post-mixed.edges.json").read_bytes()
    predecessor_record = (build / "o2.fixed.json").read_bytes()
    predecessor = json.loads(predecessor_record)
    o2_paths = {name: Path(predecessor["paths"][name]) for name in
                ("requested_ir", "optimized_ir", "opt_exe")}
    o2_inputs = {name: path.read_bytes() for name, path in o2_paths.items()}
    publication = verify_builder_archive_publication(object_bytes, image_bytes,
        report, edges, archive_record, archive_roles, codes, wrappers)
    o2_proof = verify_o2_predecessor_record(predecessor_record, o2_paths, o2_inputs,
        archive_record, archive_paths)
    prepared = archive_roles["prepared_ir"]

    def prove(obj=object_bytes, image=image_bytes, r=report, e=edges,
              requested=o2_inputs["requested_ir"], optimized=o2_inputs["optimized_ir"],
              materialized=prepared, owner_codes=codes, archive=publication,
              predecessor_proof=o2_proof):
        return verify_builder_o2_original_predicates(obj, image, r, e, requested,
            optimized, materialized, owner_codes, archive, predecessor_proof)

    proof = prove()
    final = json.loads((demo / "payload.cff.final.json").read_bytes())
    assert final["builder_o2_original_predicates"] == proof
    assert proof["three_selected_predicate_routes_verified"] is True
    assert proof["scope"] == "selected-o2-three-original-predicate-routes-win64-v1"
    assert proof["object_sha256"] == hashlib.sha256(object_bytes).hexdigest()
    assert proof["observation_body_effect_verified"] is False

    optimized_normalized = o2_inputs["optimized_ir"].replace(b"\r\n", b"\n")
    optimized_body = _ir_function(optimized_normalized.decode(), WRAPPER).encode()
    wrong_field_body = optimized_body.replace(b"ptr %3, i64 8", b"ptr %3, i64 0", 1)
    wrong_field = optimized_normalized.replace(optimized_body, wrong_field_body, 1)
    assert wrong_field != o2_inputs["optimized_ir"]
    refused("wrong optimized field", lambda: prove(optimized=wrong_field,
        predecessor_proof={**o2_proof, "optimized_ir_sha256": hashlib.sha256(
            wrong_field).hexdigest()}), "no longer reads generation")
    requested_normalized = o2_inputs["requested_ir"].replace(b"\r\n", b"\n")
    requested_body = _ir_function(requested_normalized.decode(), WRAPPER).encode()
    wrong_argument_body = requested_body.replace(
        b"icmp ne i64 %20, %24", b"icmp ne i64 %20, %20", 1)
    wrong_argument = requested_normalized.replace(requested_body, wrong_argument_body, 1)
    assert wrong_argument != o2_inputs["requested_ir"]
    refused("wrong requested argument", lambda: prove(requested=wrong_argument,
        predecessor_proof={**o2_proof, "requested_ir_sha256": hashlib.sha256(
            wrong_argument).hexdigest()}), "unmodeled original predicate")
    branch = re.search(rb"br i1 %\.not, label %\d+, label %\d+, !pyobf\.cff\.site !(\d+)",
                       optimized_body)
    assert branch is not None
    wrong_metadata_body = optimized_body[:branch.start(1)] + b"0" + \
        optimized_body[branch.end(1):]
    wrong_metadata = optimized_normalized.replace(
        optimized_body, wrong_metadata_body, 1)
    refused("wrong optimized metadata", lambda: prove(optimized=wrong_metadata,
        predecessor_proof={**o2_proof, "optimized_ir_sha256": hashlib.sha256(
            wrong_metadata).hexdigest()}), "metadata")
    changed_report = json.loads(report)
    row = next(row for row in changed_report["functions"] if row["function"] == WRAPPER)
    edge = row["runtime_contribution"]["original_edges"]["edges"][0]
    edge["dispatch_state"] ^= 1
    refused("altered report edge", lambda: prove(r=json.dumps(changed_report).encode()),
            "wrapper comparison does not route")
    refused("stale edge plan", lambda: prove(e=edges + b" "), "frozen edge plan")
    refused("wrong archive proof", lambda: prove(archive={**publication,
        "object_sha256": "0" * 64}), "two selected archive")

    with TemporaryDirectory(dir=build) as directory:
        scratch = Path(directory)
        items = _instructions(codes[WRAPPER], image_bytes, WRAPPER)
        compare = [item for item in items if item.raw == b"\x4d\x39\xc8"]
        assert len(compare) == 1
        changed_obj, changed_image = _paired_field(object_bytes, image_bytes,
            WRAPPER, compare[0], 0, b"\x4d\x39\xc0")
        changed_codes, changed_wrappers = _code(objdump, scratch, changed_image, names)
        # The previous archive proof only covers compute; it accepts the
        # paired wrapper self-comparison in this actual product.
        previous = verify_builder_archive_publication(changed_obj, changed_image,
            report, edges, archive_record, archive_roles, changed_codes,
            changed_wrappers)
        assert previous["publication_route_verified"] is True
        refused("paired wrapper self-compare", lambda: prove(obj=changed_obj,
            image=changed_image, owner_codes=changed_codes,
            archive={**publication, "object_sha256": hashlib.sha256(changed_obj).hexdigest(),
                     "image_sha256": hashlib.sha256(changed_image).hexdigest()}),
            "wrapper predicate no longer compares")
        cache_zero = [item for item in items if item.raw.startswith(
            b"\xc7\x84\x24\xb8\x00\x00\x00") and len(item.raw) == 11 and
            item.address < compare[0].address]
        assert len(cache_zero) == 1
        zero_obj, zero_image = _paired_field(object_bytes, image_bytes, WRAPPER,
            cache_zero[0], 0, bytes.fromhex("41c7c0000000000f1f4000"))
        zero_codes, zero_wrappers = _code(objdump, scratch, zero_image, names)
        old_zero = verify_builder_archive_publication(zero_obj, zero_image,
            report, edges, archive_record, archive_roles, zero_codes, zero_wrappers)
        assert old_zero["publication_route_verified"] is True
        refused("paired post-reload r8d zero", lambda: prove(obj=zero_obj,
            image=zero_image, owner_codes=zero_codes,
            archive={**publication, "object_sha256": hashlib.sha256(zero_obj).hexdigest(),
                     "image_sha256": hashlib.sha256(zero_image).hexdigest()}),
            "wrapper comparison window")
        state_obj, state_image = _paired_field(object_bytes, image_bytes,
            WRAPPER, cache_zero[0], 3, bytes.fromhex("14010000"))
        state_codes, state_wrappers = _code(objdump, scratch, state_image, names)
        assert verify_builder_archive_publication(state_obj, state_image,
            report, edges, archive_record, archive_roles, state_codes,
            state_wrappers)["publication_route_verified"] is True
        refused("paired cache clear into CFF state", lambda: prove(obj=state_obj,
            image=state_image, owner_codes=state_codes,
            archive={**publication, "object_sha256": hashlib.sha256(state_obj).hexdigest(),
                     "image_sha256": hashlib.sha256(state_image).hexdigest()}),
            "clears a different cache or control slot")
        pre_reload = [item for item in items if item.opcode == "movl" and
                      item.operands == ("%eax", "0xd4(%rsp)") and
                      item.raw == bytes.fromhex("898424d4000000") and
                      item.address < cache_zero[0].address]
        assert len(pre_reload) == 1
        for label, offset, replacement in (
                ("pre-reload key write into CFF state", 3, bytes.fromhex("14010000")),
                ("pre-reload frame replacement", 0, bytes.fromhex("4889c40f1f4000"))):
            altered_obj, altered_image = _paired_field(object_bytes, image_bytes,
                WRAPPER, pre_reload[0], offset, replacement)
            altered_codes, altered_wrappers = _code(objdump, scratch, altered_image, names)
            assert verify_builder_archive_publication(altered_obj, altered_image,
                report, edges, archive_record, archive_roles, altered_codes,
                altered_wrappers)["publication_route_verified"] is True
            refused(label, lambda obj=altered_obj, image=altered_image,
                    owner_codes=altered_codes: prove(obj=obj, image=image,
                    owner_codes=owner_codes, archive={**publication,
                    "object_sha256": hashlib.sha256(obj).hexdigest(),
                    "image_sha256": hashlib.sha256(image).hexdigest()}),
                    "wrapper pre-reload key")
        for label, replacement, reason in (
                ("post-reload frame change", bytes.fromhex("bc00000000660f1f440000"),
                 "wrapper comparison window"),
                ("post-reload control change", bytes.fromhex("e906000000660f1f440000"),
                 "no unique parent observation call")):
            altered_obj, altered_image = _paired_field(object_bytes, image_bytes,
                WRAPPER, cache_zero[0], 0, replacement)
            altered_codes, altered_wrappers = _code(objdump, scratch, altered_image, names)
            assert verify_builder_archive_publication(altered_obj, altered_image,
                report, edges, archive_record, archive_roles, altered_codes,
                altered_wrappers)["publication_route_verified"] is True
            refused(label, lambda obj=altered_obj, image=altered_image,
                    owner_codes=altered_codes: prove(obj=obj, image=image,
                    owner_codes=owner_codes, archive={**publication,
                    "object_sha256": hashlib.sha256(obj).hexdigest(),
                    "image_sha256": hashlib.sha256(image).hexdigest()}),
                    reason)
        selector = items[items.index(compare[0]) + 1]
        assert selector.raw == b"\x0f\x44\xca"
        polarity_obj, polarity_image = _paired_field(object_bytes, image_bytes,
            WRAPPER, selector, 0, b"\x0f\x45\xca")
        polarity_codes, _ = _code(objdump, scratch, polarity_image, names)
        refused("paired wrapper polarity", lambda: prove(obj=polarity_obj,
            image=polarity_image, owner_codes=polarity_codes,
            archive={**publication, "object_sha256": hashlib.sha256(polarity_obj).hexdigest(),
                     "image_sha256": hashlib.sha256(polarity_image).hexdigest()}),
            "optimized wrapper equality polarity")

        replay_record = json.loads((build / "builder.replay.json").read_bytes())
        paths = paths_for(build, replay_record)
        fixed = paths["receipt"].read_bytes()
        receipt_inputs = {role: paths[role].read_bytes() for role in REPLAY_ROLES}
        assert verify_receipt(fixed, receipt_inputs, profile=REPLAY_PROFILE)["verified"]
        refused("fixed builder object replay", lambda: verify_receipt(fixed,
            {**receipt_inputs, "object": changed_obj}, profile=REPLAY_PROFILE),
            "object")
        mutated_object = scratch / "changed.obj"
        mutated_image = scratch / "changed.dll"
        stale_output = scratch / "stale-final.json"
        mutated_object.write_bytes(changed_obj)
        mutated_image.write_bytes(changed_image)
        stale_output.write_bytes((demo / "payload.cff.final.json").read_bytes())
        stale = finalizer(build, {**paths, "object": mutated_object,
                                  "image": mutated_image}, stale_output, replay=True)
        assert stale.returncode != 0 and "builder receipt" in stale.stderr.lower(), stale.stderr
        assert not stale_output.exists(), "rejected finalizer left stale approved JSON"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    args = parser.parse_args()
    check(args.build.resolve())


if __name__ == "__main__":
    main()
