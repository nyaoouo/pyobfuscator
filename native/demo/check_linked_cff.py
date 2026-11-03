"""Check that the linked demo DLL retains the selected relative-tree machine-code shape."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from cff_transition_evidence import check_transition_evidence
from cff_data_evidence import check_data_evidence
from cff_archive_evidence import check_archive_evidence
from cff_reference_evidence import check_reference_evidence
from cff_frame_evidence import check_frame_evidence
from cff_preparation_evidence import check_preparation_evidence
from cff_local_evidence import check_local_evidence
from cff_external_evidence import check_external_evidence
from cff_import_evidence import check_import_evidence
from cff_path_fold_evidence import check_path_fold_evidence
from cff_contribution_evidence import check_contribution_evidence
from cff_contribution_policy import check_source_mixed_private_policy
from cff_source_mixed_arguments import check_private_arguments
from cff_source_mixed_original_edges import check_source_mixed_original_edges
from cff_source_mixed_bounded_edges import check_source_mixed_bounded_edges
from cff_joint_machine_evidence import MEASURED, OWNED, verify_joint_machine


def clear_final_output(args):
    if args.output is None:
        return
    origin = "source-mixed private policy" if args.contribution_input else "linked CFF final"
    output = args.output
    temporary = output.with_name(output.name + ".tmp")
    paths = [path for name, path in vars(args).items()
             if name != "output" and isinstance(path, Path)]
    for kind, roles in (("outer builder", args.outer_builder_role),
                        ("archive origin", args.archive_origin_role)):
        for role in roles:
            if "=" not in role or not role.split("=", 1)[1]:
                raise SystemExit(f"{kind} role needs a nonempty path")
            paths.append(Path(role.split("=", 1)[1]))
    for path in paths:
        try:
            if any(candidate.resolve() == path.resolve() or
                   candidate.exists() and path.exists() and candidate.samefile(path)
                   for candidate in (output, temporary)):
                raise SystemExit(f"{origin}: final output aliases an input")
        except OSError as error:
            raise SystemExit(f"{origin}: cannot compare output path: {error}") from error
    try:
        output.unlink(missing_ok=True)
    except OSError as error:
        raise SystemExit(f"{origin}: cannot clear final output: {error}") from error


def read_builder_inputs(args, mixed_post):
    inputs = {"image": args.image.read_bytes(), "report": args.report.read_bytes(),
              "private": (args.post_mixed_private if mixed_post else args.contribution_input).read_bytes(),
              "input_ir": args.builder_input_ir.read_bytes(),
              "object": args.builder_object.read_bytes()}
    if mixed_post:
        inputs["plan"] = args.post_mixed_plan.read_bytes()
    if args.builder_replay_record is not None:
        inputs.update({
            "transformed_ir": args.builder_transformed_ir.read_bytes(),
            "request_manifest": args.builder_request_manifest.read_bytes(),
            "recipe": args.builder_recipe.read_bytes(),
            "opt_exe": args.builder_opt_exe.read_bytes(),
            "clang_exe": args.builder_clang_exe.read_bytes(),
            "pass_plugin": args.builder_pass_plugin.read_bytes(),
            "replay_record": args.builder_replay_record.read_bytes(),
        })
    return inputs


def read_outer_builder_paths(args):
    from cff_builder_receipt import OUTER_REPLAY_ROLES

    roles = {}
    for item in args.outer_builder_role:
        role, path = item.split("=", 1)
        if role in roles or role not in OUTER_REPLAY_ROLES or role == "replay_record":
            raise ValueError("duplicate or unknown outer builder role")
        roles[role] = Path(path)
    if set(roles) != set(OUTER_REPLAY_ROLES) - {"replay_record"}:
        raise ValueError("outer builder needs the exact closed role set")
    bound = {
        "image": args.image, "report": args.report,
        "object": args.owner_object, "inventory": args.owner_inventory,
        "release_report": args.post_release_report,
        "owner_plan": args.owner_plan, "release_plan": args.post_release_plan,
        "private": args.post_private, "scoped": args.post_scoped,
        "child_final": args.post_child_final, "child_image": args.post_child_image,
        "release_material": args.post_join_material,
        "mixed_plan": args.post_join_mixed_plan,
    }
    if any(path is None or roles[role].resolve() != path.resolve()
           for role, path in bound.items()):
        raise ValueError("outer builder roles differ from finalizer inputs")
    return roles


def read_source_mixed_helper_codes(objdump, image):
    codes = {}
    for name in (OWNED, MEASURED):
        try:
            process = subprocess.run(
                [str(objdump), "-d", f"--disassemble-symbols={name}", str(image)],
                capture_output=True, text=True, timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SystemExit(f"source-mixed helper disassembly failed for {name}: {error}") from error
        if process.returncode:
            raise SystemExit(f"objdump failed for source-mixed helper {name}: {process.stderr}")
        code = process.stdout.lower()
        if not re.search(rf"<{re.escape(name)}>:", code):
            raise SystemExit(f"source-mixed linked helper is absent: {name}")
        codes[name] = code
    return codes


def read_archive_wrapper_codes(objdump, image, bindings_bytes):
    document = json.loads(bindings_bytes)
    rows = document["records"]
    codes = {}
    for index in range(28, 34):
        name = rows[index]["wrapper"]
        if not isinstance(name, str) or not re.fullmatch(r"__pyobf_archive_[0-9a-f]{32}_\d+", name):
            raise ValueError("archive predicate wrapper name is malformed")
        try:
            process = subprocess.run(
                [str(objdump), "-d", f"--disassemble-symbols={name}", str(image)],
                capture_output=True, text=True, timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError(f"archive wrapper disassembly failed for {name}: {error}") from error
        if process.returncode:
            raise ValueError(f"archive wrapper objdump failed for {name}: {process.stderr[:200]}")
        code = process.stdout.lower()
        if not re.search(rf"<{re.escape(name)}>:", code):
            raise ValueError(f"archive wrapper is absent from linked PE: {name}")
        codes[name] = code
    if len(codes) != 6:
        raise ValueError("archive predicate wrappers are not distinct")
    return codes


def read_binding_effect_codes(objdump, image, names):
    if (type(names) is not tuple or len(names) != 3 or len(set(names)) != 3 or
            any(type(name) is not str or re.fullmatch(r"_[A-Za-z0-9_]+", name) is None
                for name in names)):
        raise ValueError("binding-status effect symbols are not a closed three-function set")
    codes = {}
    for name in names:
        try:
            process = subprocess.run(
                [str(objdump), "-d", f"--disassemble-symbols={name}", str(image)],
                capture_output=True, text=True, timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError(f"binding-status effect disassembly failed for {name}: {error}") from error
        if process.returncode:
            raise ValueError(f"binding-status effect objdump failed for {name}: {process.stderr[:200]}")
        code = process.stdout.lower()
        if not re.search(rf"<{re.escape(name.lower())}>:", code):
            raise ValueError(f"binding-status effect is absent from linked PE: {name}")
        codes[name] = code
    return codes


def read_archive_decoder_codes(objdump, image, names):
    if (type(names) is not tuple or len(names) != 5 or len(set(names)) != 5 or
            any(type(name) is not str or re.fullmatch(r"_[A-Za-z0-9_]+", name) is None
                for name in names)):
        raise ValueError("archive decoder symbols are not a closed five-function set")
    codes = {}
    for name in names:
        try:
            process = subprocess.run(
                [str(objdump), "-d", f"--disassemble-symbols={name}", str(image)],
                capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError(f"archive decoder disassembly failed for {name}: {error}") from error
        if process.returncode:
            raise ValueError(f"archive decoder objdump failed for {name}: {process.stderr[:200]}")
        code = process.stdout.lower()
        if not re.search(rf"<{re.escape(name.lower())}>:", code):
            raise ValueError(f"archive decoder is absent from linked PE: {name}")
        codes[name] = code
    return codes


def read_bound_call_code(objdump, image, name):
    if type(name) is not str or re.fullmatch(r"_[A-Za-z0-9_]+", name) is None:
        raise ValueError("bound-call symbol is not one exact function name")
    try:
        process = subprocess.run(
            [str(objdump), "-d", f"--disassemble-symbols={name}", str(image)],
            capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"bound-call disassembly failed for {name}: {error}") from error
    if process.returncode:
        raise ValueError(f"bound-call objdump failed for {name}: {process.stderr[:200]}")
    code = process.stdout.lower()
    if not re.search(rf"<{re.escape(name.lower())}>:", code):
        raise ValueError(f"bound-call function is absent from linked PE: {name}")
    return code


def checked_original_edge_result(result, plan_bytes):
    expected = {
        "verified": True,
        "profile": "schema4-original-edges-two-v1",
        "planned_edges": 2,
        "selected_edges": 2,
        "bound_edges": 2,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
    }
    if (type(result) is not dict or result != expected or
            type(result.get("verified")) is not bool or
            any(type(result.get(key)) is not int for key in
                ("planned_edges", "selected_edges", "bound_edges"))):
        raise ValueError("source-mixed original-edge proof returned an incomplete or forged result")
    return result


def checked_bounded_edge_result(result, plan_bytes):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("bounded original-edge plan has duplicate JSON keys")
            value[key] = item
        return value

    def nonfinite(_):
        raise ValueError("bounded original-edge plan contains a nonfinite value")

    if len(plan_bytes) > 65536:
        raise ValueError("bounded original-edge plan exceeds the input limit")
    try:
        plan = json.loads(plan_bytes.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=nonfinite)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("bounded original-edge plan is invalid JSON") from error
    if (type(plan) is not dict or set(plan) != {"schema_version", "profile", "input_ir_encoding",
            "input_ir_sha256", "owners"} or type(plan["schema_version"]) is not int or
            plan["schema_version"] != 2 or plan["profile"] != "schema4-original-edges-bounded-v2" or
            plan["input_ir_encoding"] != "llvm-module-print-v1" or
            type(plan["input_ir_sha256"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", plan["input_ir_sha256"]) is None or
            type(plan["owners"]) is not list or len(plan["owners"]) != 1):
        raise ValueError("bounded original-edge plan has an unsupported profile")
    owner = plan["owners"][0]
    if (type(owner) is not dict or set(owner) != {"owner", "recipe", "edges"} or
            type(owner["owner"]) is not str or not owner["owner"] or
            type(owner["recipe"]) is not dict or type(owner["edges"]) is not list or
            not 3 <= len(owner["edges"]) <= 8):
        raise ValueError("bounded original-edge plan needs one owner and three to eight edges")
    count = len(owner["edges"])
    expected = {"verified": True, "profile": "schema4-original-edges-bounded-v2",
        "planned_edges": count, "selected_edges": count, "bound_edges": count,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest()}
    if (type(result) is not dict or result != expected or
            type(result.get("verified")) is not bool or
            any(type(result.get(key)) is not int for key in
                ("planned_edges", "selected_edges", "bound_edges"))):
        raise ValueError("bounded original-edge proof returned an incomplete or forged result")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("objdump", type=Path)
    parser.add_argument("image", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--owner-object", type=Path)
    parser.add_argument("--owner-inventory", type=Path)
    parser.add_argument("--owner-plan", type=Path)
    parser.add_argument("--post-release-report", type=Path)
    parser.add_argument("--post-release-plan", type=Path)
    parser.add_argument("--post-child-image", type=Path)
    parser.add_argument("--post-child-final", type=Path)
    parser.add_argument("--post-child-raw", type=Path)
    parser.add_argument("--post-private", type=Path)
    parser.add_argument("--post-scoped", type=Path)
    parser.add_argument("--post-join-mixed-plan", type=Path)
    parser.add_argument("--post-join-material", type=Path)
    parser.add_argument("--contribution-input", type=Path,
                        help="compare one schema4 source-mixed report with independently supplied private build input")
    parser.add_argument("--source-mixed-original-edges", type=Path,
                        help="require the private exact-IR two-edge plan and linked original-edge proof")
    parser.add_argument("--source-mixed-bounded-edges", type=Path,
                        help="require the private schema2 three-to-eight-edge plan and linked proof")
    parser.add_argument("--post-mixed-plan", type=Path,
                        help="require the frozen two-owner POST original-edge plan")
    parser.add_argument("--post-mixed-private", type=Path)
    parser.add_argument("--post-mixed-material", type=Path)
    parser.add_argument("--post-mixed-scoped", type=Path)
    parser.add_argument("--builder-receipt", type=Path,
                        help="fixed trusted-builder receipt for exact mixed POST build inputs")
    parser.add_argument("--builder-input-ir", type=Path)
    parser.add_argument("--builder-object", type=Path)
    parser.add_argument("--builder-subjects", action="store_true",
                        help="require exact mixed owner/helper COFF-to-PE function extents")
    parser.add_argument("--builder-entry-states", action="store_true",
                        help="require mixed owner entry immediates from frozen CFG seeds")
    parser.add_argument("--builder-local-callees", action="store_true",
                        help="require exact mixed binding callees and a bounded status route")
    parser.add_argument("--builder-local-callees-seed", type=int)
    parser.add_argument("--builder-helper-arguments", action="store_true",
                        help="require exact mixed helper arguments at the binding call")
    parser.add_argument("--builder-binding-status-effects", action="store_true",
                        help="require the local binding-status pointer and generation routes")
    parser.add_argument("--builder-context-availability-effect", action="store_true",
                        help="require the called context-availability closing and lock route")
    parser.add_argument("--builder-bound-call", action="store_true",
                        help="bind the local publication guard and retained invoke argument route")
    parser.add_argument("--builder-retain-local", action="store_true",
                        help="bind selected retain-context guards and local increment route")
    parser.add_argument("--builder-invoke-local", action="store_true",
                        help="bind selected invoke request, callback and completion route")
    parser.add_argument("--builder-original-predicates", action="store_true",
                        help="bind mixed POST original conditions to their linked PE routes")
    parser.add_argument("--parent-callback", action="store_true",
                        help="require the outer creator's exact dispatch callback assignment")
    parser.add_argument("--outer-builder-receipt", type=Path,
                        help="externally frozen outer compiler and final-PE consistency receipt")
    parser.add_argument("--outer-builder-record", type=Path)
    parser.add_argument("--outer-builder-role", action="append", default=[],
                        help="exact role=path input for the outer trusted-builder profile")
    parser.add_argument("--builder-replay-record", type=Path)
    parser.add_argument("--builder-transformed-ir", type=Path)
    parser.add_argument("--builder-request-manifest", type=Path)
    parser.add_argument("--builder-recipe", type=Path)
    parser.add_argument("--builder-opt-exe", type=Path)
    parser.add_argument("--builder-clang-exe", type=Path)
    parser.add_argument("--builder-pass-plugin", type=Path)
    parser.add_argument("--archive-origin-record", type=Path)
    parser.add_argument("--archive-origin-role", action="append", default=[],
                        help="exact role=path input for the fixed G3 archive-origin record")
    parser.add_argument("--builder-o2-predecessor-record", type=Path)
    parser.add_argument("--builder-o2-requested-ir", type=Path)
    parser.add_argument("--builder-o2-optimized-ir", type=Path)
    parser.add_argument("--builder-o2-opt-exe", type=Path)
    parser.add_argument("--builder-archive-publication", action="store_true",
                        help="bind selected O2 archive predicate publication and read routes")
    parser.add_argument("--builder-archive-decoder-linkage", action="store_true",
                        help="bind the selected archive decoder call and argument chain")
    parser.add_argument("--builder-archive-first-use-arm", action="store_true",
                        help="bind the selected conditional archive cache first-use arm")
    parser.add_argument("--builder-archive-entry-route", action="store_true",
                        help="bind the selected archive entry success path to first-use")
    parser.add_argument("--builder-o2-original-predicates", action="store_true",
                        help="bind the three selected O2 original predicate routes")
    parser.add_argument("--check-joint-caller-flow", action="store_true",
                        help="check bounded schema4 caller setup; cross-call helper effects remain unverified")
    args = parser.parse_args()
    clear_final_output(args)
    if args.source_mixed_original_edges is not None and args.source_mixed_bounded_edges is not None:
        raise SystemExit("source-mixed original-edge proof modes are mutually exclusive")
    mixed_inputs = (args.post_mixed_plan, args.post_mixed_private,
                    args.post_mixed_material, args.post_mixed_scoped)
    mixed_post = any(mixed_inputs)
    if mixed_post and (not all(mixed_inputs) or args.source_mixed_original_edges is not None or
                       args.source_mixed_bounded_edges is not None or args.contribution_input is not None):
        raise SystemExit("mixed POST final proof needs four exact inputs and its own edge mode")
    builder_inputs = (args.builder_receipt, args.builder_input_ir, args.builder_object)
    if any(builder_inputs) and (not all(builder_inputs) or
                                not (mixed_post or args.contribution_input is not None)):
        raise SystemExit("builder receipt proof needs a fixed receipt, input IR, object and a private source policy")
    if args.builder_subjects and (not mixed_post or not all(builder_inputs)):
        raise SystemExit("builder subjects need mixed POST and a fixed builder receipt")
    if args.builder_entry_states and not args.builder_subjects:
        raise SystemExit("builder entry states need exact builder subjects")
    if args.builder_local_callees != (args.builder_local_callees_seed is not None) or (
            args.builder_local_callees and not args.builder_entry_states):
        raise SystemExit("builder local callees need a CFF seed and exact mixed entry states")
    if args.builder_helper_arguments and not args.builder_local_callees:
        raise SystemExit("builder helper arguments need the local callee proof")
    if args.builder_binding_status_effects and not args.builder_helper_arguments:
        raise SystemExit("builder binding-status effects need exact helper arguments")
    if args.builder_context_availability_effect and not args.builder_binding_status_effects:
        raise SystemExit("builder context-availability effect needs binding-status effects")
    if args.builder_bound_call and not args.builder_context_availability_effect:
        raise SystemExit("builder bound-call route needs context-availability effects")
    if args.builder_retain_local and not args.builder_bound_call:
        raise SystemExit("builder retain local route needs bound-call route")
    if args.builder_invoke_local and not (args.builder_bound_call and args.builder_retain_local):
        raise SystemExit("builder invoke local route needs bound-call and retain local routes")
    if args.builder_original_predicates and not args.builder_entry_states:
        raise SystemExit("builder original predicates need exact mixed entry states")
    if args.parent_callback and (mixed_post or args.owner_object is None or
                                 args.post_child_final is None):
        raise SystemExit("parent callback needs an outer owner object and child final report")
    outer_builder_requested = (args.outer_builder_receipt is not None or
                               args.outer_builder_record is not None or
                               bool(args.outer_builder_role))
    if outer_builder_requested and (args.outer_builder_receipt is None or
                                    args.outer_builder_record is None or
                                    not args.parent_callback):
        raise SystemExit("outer builder consistency needs its receipt, record and parent callback")
    replay_inputs = (args.builder_replay_record, args.builder_transformed_ir,
                     args.builder_request_manifest, args.builder_recipe,
                     args.builder_opt_exe, args.builder_clang_exe,
                     args.builder_pass_plugin)
    if any(replay_inputs) and (not all(replay_inputs) or not args.builder_entry_states or
                               not mixed_post or not all(builder_inputs)):
        raise SystemExit("builder replay needs all replay inputs, mixed POST and exact entry states")
    archive_origin_requested = (args.archive_origin_record is not None or
                                bool(args.archive_origin_role))
    if archive_origin_requested and (args.archive_origin_record is None or
                                     args.builder_replay_record is None or not mixed_post):
        raise SystemExit("archive origin needs its fixed record, child replay and mixed POST")
    if args.builder_archive_publication and (not archive_origin_requested or
                                             not args.builder_subjects or
                                             not args.builder_entry_states):
        raise SystemExit("builder archive publication needs archive origin and exact mixed subjects/entry states")
    if args.builder_archive_decoder_linkage and not args.builder_archive_publication:
        raise SystemExit("builder archive decoder linkage needs archive publication")
    if args.builder_archive_first_use_arm and not args.builder_archive_decoder_linkage:
        raise SystemExit("builder archive first-use arm needs decoder linkage")
    if args.builder_archive_entry_route and not args.builder_archive_first_use_arm:
        raise SystemExit("builder archive entry route needs the first-use arm")
    o2_paths = {"requested_ir": args.builder_o2_requested_ir,
                "optimized_ir": args.builder_o2_optimized_ir,
                "opt_exe": args.builder_o2_opt_exe}
    o2_requested = args.builder_o2_predecessor_record is not None or any(o2_paths.values())
    if o2_requested and (args.builder_o2_predecessor_record is None or
                         not all(o2_paths.values()) or not archive_origin_requested):
        raise SystemExit("builder O2 predecessor needs its fixed record, three roles and archive origin")
    if args.builder_o2_original_predicates and (not o2_requested or
                                                 not args.builder_archive_publication):
        raise SystemExit("builder O2 original predicates need O2 predecessor and archive publication")
    builder_proof = builder_receipt_bytes = builder_profile = None
    outer_builder_proof = outer_builder_receipt_bytes = outer_builder_inputs = None
    if outer_builder_requested:
        from cff_builder_receipt import OUTER_REPLAY_PROFILE, verify_receipt
        from cff_outer_builder_replay import verify_outer_replay_record

        try:
            outer_builder_paths = read_outer_builder_paths(args)
            outer_builder_receipt_bytes = args.outer_builder_receipt.read_bytes()
            outer_builder_inputs = {role: path.read_bytes()
                                    for role, path in outer_builder_paths.items()}
            outer_builder_inputs["replay_record"] = args.outer_builder_record.read_bytes()
            verify_receipt(outer_builder_receipt_bytes, outer_builder_inputs,
                           profile=OUTER_REPLAY_PROFILE)
            outer_builder_proof = verify_outer_replay_record(
                outer_builder_inputs["replay_record"], outer_builder_inputs)
        except (OSError, ValueError) as error:
            raise SystemExit(f"outer builder consistency failed: {error}") from error
    replay_proof = None
    if args.builder_receipt is not None:
        from cff_builder_receipt import PROFILE, REPLAY_PROFILE, verify_receipt
        if mixed_post:
            builder_profile = REPLAY_PROFILE if args.builder_replay_record else PROFILE
        else:
            from cff_builder_receipt import SOURCE_PROFILE
            builder_profile = SOURCE_PROFILE
        try:
            builder_receipt_bytes = args.builder_receipt.read_bytes()
            builder_proof = verify_receipt(builder_receipt_bytes,
                                           read_builder_inputs(args, mixed_post),
                                           profile=builder_profile)
        except (OSError, ValueError) as error:
            raise SystemExit(f"builder receipt verification failed: {error}") from error
        if args.builder_replay_record is not None:
            from cff_builder_replay import verify_replay_record
            try:
                replay_proof = verify_replay_record(args.builder_replay_record.read_bytes(),
                                                   read_builder_inputs(args, mixed_post))
            except (OSError, ValueError) as error:
                raise SystemExit(f"builder replay record failed: {error}") from error
    archive_origin_proof = archive_origin_bytes = archive_origin_inputs = None
    if archive_origin_requested:
        from cff_archive_origin_contract import role_paths
        from cff_archive_origin import verify_archive_origin_record

        try:
            archive_origin_paths = role_paths(args.archive_origin_role)
            if (args.archive_origin_record.resolve() in archive_origin_paths.values() or
                    archive_origin_paths["child_replay_record"] != args.builder_replay_record.resolve() or
                    archive_origin_paths["prepared_ir"] != args.builder_input_ir.resolve() or
                    archive_origin_paths["merged_requests"] != args.builder_request_manifest.resolve()):
                raise ValueError("archive roles do not join the exact child replay inputs")
            archive_origin_bytes = args.archive_origin_record.read_bytes()
            archive_origin_inputs = {role: path.read_bytes()
                                     for role, path in archive_origin_paths.items()}
            archive_origin_proof = verify_archive_origin_record(
                archive_origin_bytes, archive_origin_inputs)
        except (OSError, ValueError) as error:
            raise SystemExit(f"archive origin proof failed: {error}") from error
    o2_proof = o2_record_bytes = o2_inputs = None
    if o2_requested:
        from cff_builder_o2_predecessor import verify_o2_predecessor_record

        try:
            o2_record_bytes = args.builder_o2_predecessor_record.read_bytes()
            o2_inputs = {role: path.read_bytes() for role, path in o2_paths.items()}
            o2_proof = verify_o2_predecessor_record(
                o2_record_bytes, o2_paths, o2_inputs,
                archive_origin_bytes, archive_origin_paths)
            expected = {
                "verified": True,
                "optimizer_replay_verified": True,
                "archive_input_join_verified": True,
                "cpp_source_provenance_verified": False,
                "publisher_signature_verified": False,
                "scope": "trusted-builder-o2-predecessor-v1",
                "record_sha256": hashlib.sha256(o2_record_bytes).hexdigest(),
                **{role + "_sha256": hashlib.sha256(data).hexdigest()
                   for role, data in o2_inputs.items()},
            }
            if o2_proof != expected:
                raise ValueError("incomplete O2 predecessor proof")
        except (OSError, ValueError) as error:
            raise SystemExit(f"builder O2 predecessor proof failed: {error}") from error
    strict_plan = args.source_mixed_original_edges or args.source_mixed_bounded_edges
    report = json.loads(args.report.read_text(encoding="utf-8"))
    machine_only = {"joint_caller_pointer_provenance_verified", "joint_machine_scope",
                    "joint_return_routing_scope", "original_edge_machine"}
    if any(machine_only.intersection(row) or
           machine_only.intersection(row.get("runtime_contribution", {})) for row in report["functions"]):
        raise SystemExit("raw CFF report contains final-image-only joint machine evidence")
    private_identity = None
    if strict_plan is not None and args.contribution_input is None:
        raise SystemExit("source-mixed original-edge proof needs private contribution input")
    if args.contribution_input is not None:
        try:
            private_identity = check_source_mixed_private_policy(args.contribution_input.read_bytes(), report,
                maximum_sites=8 if args.source_mixed_bounded_edges is not None else 2)
        except (OSError, ValueError) as error:
            raise SystemExit(str(error)) from error
    owner_proof = creator_proof = parent_callback_proof = None
    owner_inputs = (args.owner_object, args.owner_inventory, args.owner_plan)
    if "owner_readers" in report or any(owner_inputs):
        if "owner_readers" not in report or not all(owner_inputs):
            raise SystemExit("owner reader evidence requires its actual object, emission inventory and early plan")
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        from owner_reader_image import verify_owner_readers
        from owner_creator_image import verify_owner_creators
        from reference_plan import parse_plan
        try:
            owner_plan = parse_plan(args.owner_plan.read_bytes())
            owner_proof = verify_owner_readers(args.image.read_bytes(), report, args.report.read_bytes(), args.owner_object.read_bytes(),
                args.owner_inventory.read_bytes(), owner_plan)
            creator_proof = verify_owner_creators(args.image.read_bytes(), report, args.report.read_bytes(),
                args.owner_object.read_bytes(), args.owner_inventory.read_bytes(), owner_plan, owner_proof)
        except (OSError, ValueError) as error: raise SystemExit(f"owner reader final evidence failed: {error}") from error
    if args.parent_callback:
        if owner_proof is None:
            raise SystemExit("parent callback needs verified outer owner readers")
        from parent_callback_image import INITIALIZE, verify_parent_callback
    if report["strategy"] != "relative-tree":
        raise SystemExit("linked CFF shape check requires relative-tree")
    selected = [row["function"] for row in report["functions"] if row["selected"]]
    if not selected or any(row["status"] != "transformed" for row in report["functions"]
                           if row["selected"]):
        raise SystemExit("linked CFF check needs fully transformed selected functions")
    joint_machine = {}
    original_edges = {}
    owner_codes = {}
    mixed_helpers = None
    parent_initialize_code = None
    for name in selected:
        row = next(row for row in report["functions"] if row["function"] == name)
        if row.get("strategy") == "relative-tree-region" and row.get("region_flow_contract_verified") is not True:
            raise SystemExit(f"linked region lacks compiler boundary/flow proof: {name}")
        process = subprocess.run(
            [str(args.objdump), "-d", f"--disassemble-symbols={name}", str(args.image)],
            capture_output=True, text=True, timeout=20,
        )
        if process.returncode:
            raise SystemExit(f"objdump failed for {name}: {process.stderr}")
        code = process.stdout.lower()
        if not re.search(rf"<{re.escape(name.lower())}>:", code):
            raise SystemExit(f"selected CFF function is absent from the linked DLL: {name}")
        if args.parent_callback and name == INITIALIZE:
            parent_initialize_code = code
        transitions = max(1, row.get("site_totals", {}).get("transition_sites", 2))
        if (len(re.findall(r"\bjae\b", code)) < 2 or
                len(re.findall(r"\bimull\s+\$0x7feb352d\b", code)) < transitions or
                len(re.findall(r"\bimull\s+\$0x846ca68b\b", code)) < transitions):
            raise SystemExit(f"linked DLL lost the expected relative-tree shape: {name}")
        components = {item["component"]: item for item in row.get("components", [])}
        if any(components.get(name, {}).get("applied", 0) for name in ("opaque-choices", "reachable-junk", "decoy-transitions")) and row.get("transition_layer_contract_verified") is not True:
            raise SystemExit(f"linked transition layers lack compiler composition proof: {name}")
        if any(components.get(name, {}).get("applied", 0) for name in ("bogus-clones", "bogus-synthesis")) and row.get("bogus_control_contract_verified") is not True:
            raise SystemExit(f"linked bogus controls lack compiler ownership proof: {name}")
        check_transition_evidence(row, code)
        check_data_evidence(row, code)
        check_archive_evidence(row, code)
        check_reference_evidence(row, code)
        check_import_evidence(row, code)
        check_path_fold_evidence(row, code)
        contribution = row.get("runtime_contribution", {})
        site_rows = contribution.get("sites")
        mixed_owner = (mixed_post and name in ("pyobf_demo_bound_compute",
                                              "pyobf_demo_protection_wrapper"))
        source_mixed_sites = (contribution.get("scheme_version") == 4 and
            contribution.get("provider") == "source-mixed-v1" and
            isinstance(site_rows, list) and (len(site_rows) == 2 or
                (args.source_mixed_bounded_edges is not None or mixed_owner) and 3 <= len(site_rows) <= 8))
        if mixed_owner:
            owner_codes[name] = code
            if mixed_helpers is None:
                mixed_helpers = read_source_mixed_helper_codes(args.objdump, args.image)
        contribution_inputs = (row, code,
            args.image.read_bytes() if source_mixed_sites else None,
            mixed_helpers if mixed_owner else
            read_source_mixed_helper_codes(args.objdump, args.image) if source_mixed_sites else None)
        if (strict_plan is None and not mixed_owner or
                contribution.get("acquisition") != "original-edges-and-explicit-points"):
            check_contribution_evidence(*contribution_inputs)
        else:
            try:
                check_contribution_evidence(*contribution_inputs,
                    allow_source_mixed_original=True,
                    allow_source_mixed_bounded=args.source_mixed_bounded_edges is not None or mixed_owner)
            except TypeError as error:
                if not any(f"unexpected keyword argument '{name}'" in str(error) for name in
                           ("allow_source_mixed_original", "allow_source_mixed_bounded")):
                    raise
                raise SystemExit("source-mixed original-edge final verifier is unavailable") from error
        if source_mixed_sites and private_identity is not None:
            try:
                check_private_arguments(args.image.read_bytes(), code, row, private_identity)
            except ValueError as error:
                raise SystemExit(str(error)) from error
        if args.source_mixed_original_edges is not None and contribution.get("acquisition") == "original-edges-and-explicit-points":
            try:
                plan_bytes = args.source_mixed_original_edges.read_bytes()
                proof = check_source_mixed_original_edges(
                    args.image.read_bytes(), code, row, args.report.read_bytes(),
                    args.contribution_input.read_bytes(), plan_bytes)
                original_edges[name] = checked_original_edge_result(proof, plan_bytes)
            except (OSError, ValueError) as error:
                raise SystemExit(f"source-mixed original-edge proof failed: {error}") from error
        if args.source_mixed_bounded_edges is not None and contribution.get("acquisition") == "original-edges-and-explicit-points":
            try:
                plan_bytes = args.source_mixed_bounded_edges.read_bytes()
                proof = check_source_mixed_bounded_edges(
                    args.image.read_bytes(), code, row, args.report.read_bytes(),
                    args.contribution_input.read_bytes(), plan_bytes, contribution_inputs[3])
                original_edges[name] = checked_bounded_edge_result(proof, plan_bytes)
            except (OSError, ValueError) as error:
                raise SystemExit(f"source-mixed bounded-edge proof failed: {error}") from error
        if args.check_joint_caller_flow and row.get("runtime_contribution", {}).get(
                "joint_helper_contract") == "source-mixed-context-v1":
            try:
                joint_machine[name] = verify_joint_machine(args.image.read_bytes(), code, report, row)
            except (OSError, ValueError) as error:
                raise SystemExit(str(error)) from error
        check_frame_evidence(report, row, code)
        check_preparation_evidence(row, code)
        check_local_evidence(row, code)
        check_external_evidence(report, row, code)
        if components:
            if (components["decoy-transitions"]["applied"] and
                    not re.search(r"\bcmovb[lq]?\b", code)):
                raise SystemExit(f"linked DLL lost its decoy transition selection: {name}")
            if (components["internal-calls"]["applied"] and
                    not re.search(r"\bcallq?\s+\*", code)):
                raise SystemExit(f"linked DLL lost indirect internal calls: {name}")
        elif row.get("strategy") == "relative-tree-deep":
            if (not re.search(r"\bimull\s+\$0x85ebca6b\b", code) or
                    not re.search(r"\bcmovb[lq]?\b", code)):
                raise SystemExit(f"linked DLL lost the legacy deep shape: {name}")
    if args.check_joint_caller_flow and len(joint_machine) != 1:
        raise SystemExit("joint caller flow check requires exactly one schema4 joint owner")
    if strict_plan is not None and len(original_edges) != 1:
        raise SystemExit("source-mixed original-edge proof requires exactly one selected owner")
    if args.parent_callback:
        if parent_initialize_code is None:
            raise SystemExit("parent callback needs selected session initializer code")
        try:
            parent_callback_proof = verify_parent_callback(
                args.owner_object.read_bytes(), args.image.read_bytes(),
                args.report.read_bytes(), parent_initialize_code)
        except (OSError, ValueError) as error:
            raise SystemExit(f"parent callback proof failed: {error}") from error
    subject_proof = entry_state_proof = local_callee_proof = helper_argument_proof = None
    predicate_proof = archive_publication_proof = archive_decoder_linkage_proof = None
    archive_first_use_proof = archive_entry_route_proof = None
    o2_predicate_proof = None
    binding_effect_proof = context_availability_proof = bound_call_proof = None
    retain_local_proof = invoke_local_proof = None
    if mixed_post:
        from cff_post_mixed_final import verify_post_mixed_child
        try:
            original_edges = verify_post_mixed_child(args.image.read_bytes(), report,
                args.report.read_bytes(), args.post_mixed_private.read_bytes(),
                args.post_mixed_plan.read_bytes(), args.post_mixed_material.read_bytes(),
                args.post_mixed_scoped.read_bytes(), owner_codes, mixed_helpers or {})
        except (OSError, ValueError) as error:
            raise SystemExit(f"mixed POST linked child proof failed: {error}") from error
        if args.builder_subjects:
            from cff_builder_subjects import verify_builder_subjects
            try:
                subject_proof = verify_builder_subjects(args.builder_object.read_bytes(),
                                                        args.image.read_bytes())
            except (OSError, ValueError) as error:
                raise SystemExit(f"builder subject proof failed: {error}") from error
        if args.builder_entry_states:
            from cff_builder_entry_states import verify_builder_entry_states
            try:
                entry_state_proof = verify_builder_entry_states(args.image.read_bytes(),
                    args.post_mixed_plan.read_bytes(), owner_codes)
            except (OSError, ValueError) as error:
                raise SystemExit(f"builder entry-state proof failed: {error}") from error
        if args.builder_local_callees:
            from cff_builder_local_callees import LOCAL_CALLEES, verify_builder_local_callees
            try:
                local_codes = {}
                for name in LOCAL_CALLEES:
                    process = subprocess.run(
                        [str(args.objdump), "-d", f"--disassemble-symbols={name}", str(args.image)],
                        capture_output=True, text=True, timeout=20)
                    if process.returncode:
                        raise ValueError(f"objdump failed for {name}: {process.stderr[:200]}")
                    code = process.stdout.lower()
                    if not re.search(rf"<{re.escape(name.lower())}>:", code):
                        raise ValueError(f"linked local callee is absent: {name}")
                    local_codes[name] = code
                local_callee_proof = verify_builder_local_callees(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    args.report.read_bytes(), args.builder_local_callees_seed,
                    mixed_helpers or {}, local_codes)
            except (OSError, subprocess.TimeoutExpired, ValueError) as error:
                raise SystemExit(f"builder local callee proof failed: {error}") from error
        if args.builder_helper_arguments:
            from cff_builder_helper_arguments import verify_builder_helper_arguments
            try:
                helper_argument_proof = verify_builder_helper_arguments(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    mixed_helpers or {}, local_callee_proof)
            except (OSError, ValueError) as error:
                raise SystemExit(f"builder helper-argument proof failed: {error}") from error
        if args.builder_binding_status_effects:
            from cff_builder_binding_status_effects import (EFFECT_CALLEES,
                verify_builder_binding_status_effects)

            try:
                effect_codes = read_binding_effect_codes(args.objdump, args.image, EFFECT_CALLEES)
                binding_effect_proof = verify_builder_binding_status_effects(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    args.report.read_bytes(), local_codes, effect_codes)
                expected = {
                    "object_sha256": hashlib.sha256(args.builder_object.read_bytes()).hexdigest(),
                    "image_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
                    "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
                }
                if (type(binding_effect_proof) is not dict or
                        binding_effect_proof.get("verified") is not True or
                        binding_effect_proof.get("state_pointer_identity_verified") is not True or
                        binding_effect_proof.get("generation_guard_verified") is not True or
                        binding_effect_proof.get("availability_route_verified") is not True or
                        binding_effect_proof.get("transitive_binding_closed") is not False or
                        any(binding_effect_proof.get(name) != digest
                            for name, digest in expected.items())):
                    raise ValueError("incomplete binding-status effect proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder binding-status effects proof failed: {error}") from error
        if args.builder_context_availability_effect:
            from cff_builder_context_availability import (CONTEXT_EFFECT_CALLEES,
                verify_builder_context_availability)

            try:
                context_codes = read_binding_effect_codes(
                    args.objdump, args.image, CONTEXT_EFFECT_CALLEES)
                context_availability_proof = verify_builder_context_availability(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    args.report.read_bytes(), context_codes)
                expected = {
                    "object_sha256": hashlib.sha256(args.builder_object.read_bytes()).hexdigest(),
                    "image_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
                    "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
                }
                if (type(context_availability_proof) is not dict or
                        context_availability_proof.get("verified") is not True or
                        context_availability_proof.get("context_availability_body_verified") is not True or
                        context_availability_proof.get("closing_field_route_verified") is not True or
                        context_availability_proof.get("lock_pair_route_verified") is not True or
                        context_availability_proof.get("platform_lock_effect_verified") is not False or
                        context_availability_proof.get("transitive_binding_closed") is not False or
                        any(context_availability_proof.get(name) != digest
                            for name, digest in expected.items())):
                    raise ValueError("incomplete context-availability effect proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder context-availability effect proof failed: {error}") from error
        if args.builder_bound_call:
            from cff_builder_bound_call import BOUND_CALL, verify_builder_bound_call

            try:
                bound_call_code = read_bound_call_code(args.objdump, args.image, BOUND_CALL)
                bound_call_proof = verify_builder_bound_call(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    args.report.read_bytes(), {BOUND_CALL: bound_call_code})
                expected = {
                    "object_sha256": hashlib.sha256(args.builder_object.read_bytes()).hexdigest(),
                    "image_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
                    "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
                }
                if (type(bound_call_proof) is not dict or
                        any(bound_call_proof.get(name) is not True for name in
                            ("verified", "pointer_guard_verified", "retain_status_route_verified",
                             "captured_lease_route_verified", "invoke_argument_route_verified")) or
                        any(bound_call_proof.get(name) is not False for name in
                            ("publication_source_verified", "retain_effect_verified",
                             "invoke_body_verified", "platform_lock_effect_verified",
                             "transitive_binding_closed")) or
                        any(bound_call_proof.get(name) != digest
                            for name, digest in expected.items())):
                    raise ValueError("incomplete bound-call route proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder bound-call route proof failed: {error}") from error
        if args.builder_retain_local:
            from cff_builder_bound_call import RETAIN
            from cff_builder_retain_local import verify_builder_retain_local

            try:
                retain_code = read_bound_call_code(args.objdump, args.image, RETAIN)
                retain_local_proof = verify_builder_retain_local(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    args.report.read_bytes(), {RETAIN: retain_code})
                expected = {
                    "object_sha256": hashlib.sha256(args.builder_object.read_bytes()).hexdigest(),
                    "image_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
                    "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
                }
                if (type(retain_local_proof) is not dict or
                        retain_local_proof.get("scope") != "selected-retain-local-increment-win64-v1" or
                        any(retain_local_proof.get(name) is not True for name in
                            ("verified", "selected_retain_route_verified", "closing_guard_verified",
                             "reference_limit_guard_verified", "increment_store_verified",
                             "status_route_verified", "lock_pair_route_verified")) or
                        any(retain_local_proof.get(name) is not False for name in
                            ("full_retain_effect_verified", "platform_lock_effect_verified",
                             "publication_source_verified", "invoke_body_verified",
                             "callback_effect_verified", "transitive_binding_closed")) or
                        any(retain_local_proof.get(name) != digest
                            for name, digest in expected.items())):
                    raise ValueError("incomplete retain local route proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder retain local route proof failed: {error}") from error
        if args.builder_invoke_local:
            from cff_builder_bound_call import INVOKE
            from cff_builder_invoke_local import verify_builder_invoke_local

            try:
                invoke_code = read_bound_call_code(args.objdump, args.image, INVOKE)
                invoke_local_proof = verify_builder_invoke_local(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    args.report.read_bytes(), {INVOKE: invoke_code})
                expected = {
                    "object_sha256": hashlib.sha256(args.builder_object.read_bytes()).hexdigest(),
                    "image_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
                    "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
                }
                if (type(invoke_local_proof) is not dict or
                        invoke_local_proof.get("scope") != "selected-invoke-local-route-win64-v1" or
                        any(invoke_local_proof.get(name) is not True for name in
                            ("verified", "request_guard_route_verified", "admit_status_route_verified",
                             "callback_argument_route_verified", "callback_call_route_verified",
                             "complete_call_route_verified", "result_return_route_verified")) or
                        any(invoke_local_proof.get(name) is not False for name in
                            ("admit_effect_verified", "complete_effect_verified",
                             "callback_identity_verified", "callback_effect_verified",
                             "platform_lock_effect_verified", "runtime_memory_integrity_verified",
                             "transitive_binding_closed")) or
                        any(invoke_local_proof.get(name) != digest
                            for name, digest in expected.items())):
                    raise ValueError("incomplete invoke local route proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder invoke local route proof failed: {error}") from error
        if args.builder_original_predicates:
            from cff_builder_original_predicates import verify_builder_original_predicates

            try:
                predicate_proof = verify_builder_original_predicates(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    args.report.read_bytes(), args.builder_input_ir.read_bytes(),
                    args.post_mixed_plan.read_bytes(), owner_codes)
            except (OSError, ValueError) as error:
                raise SystemExit(f"builder original-predicate proof failed: {error}") from error
        if args.builder_archive_publication:
            from cff_builder_archive_publication import verify_builder_archive_publication

            try:
                wrappers = read_archive_wrapper_codes(
                    args.objdump, args.image, archive_origin_inputs["bindings"])
                archive_publication_proof = verify_builder_archive_publication(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    args.report.read_bytes(), args.post_mixed_plan.read_bytes(),
                    archive_origin_bytes, archive_origin_inputs, owner_codes, wrappers)
                expected = {
                    "object_sha256": hashlib.sha256(args.builder_object.read_bytes()).hexdigest(),
                    "image_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
                    "archive_record_sha256": hashlib.sha256(archive_origin_bytes).hexdigest(),
                }
                if (type(archive_publication_proof) is not dict or
                        archive_publication_proof.get("verified") is not True or
                        archive_publication_proof.get("publication_route_verified") is not True or
                        archive_publication_proof.get("decoder_effect_verified") is not False or
                        archive_publication_proof.get("original_predicate_equivalence_verified") is not False or
                        any(archive_publication_proof.get(name) != digest
                            for name, digest in expected.items())):
                    raise ValueError("incomplete archive publication proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder archive publication proof failed: {error}") from error
        if args.builder_o2_original_predicates:
            from cff_builder_o2_original_predicates import verify_builder_o2_original_predicates

            try:
                object_bytes = args.builder_object.read_bytes()
                image_bytes = args.image.read_bytes()
                report_bytes = args.report.read_bytes()
                edge_plan_bytes = args.post_mixed_plan.read_bytes()
                prepared_ir_bytes = archive_origin_inputs["prepared_ir"]
                o2_predicate_proof = verify_builder_o2_original_predicates(
                    object_bytes, image_bytes, report_bytes, edge_plan_bytes,
                    o2_inputs["requested_ir"], o2_inputs["optimized_ir"],
                    prepared_ir_bytes, owner_codes,
                    archive_publication_proof, o2_proof)
                expected = {
                    "verified": True,
                    "wrapper_source_route_verified": True,
                    "wrapper_machine_route_verified": True,
                    "three_selected_predicate_routes_verified": True,
                    "observation_body_effect_verified": False,
                    "callback_effect_verified": False,
                    "decoder_cache_effect_verified": False,
                    "runtime_loaded_bytes_verified": False,
                    "general_o2_equivalence_verified": False,
                    "scope": "selected-o2-three-original-predicate-routes-win64-v1",
                    "o2_record_sha256": hashlib.sha256(o2_record_bytes).hexdigest(),
                    "archive_record_sha256": hashlib.sha256(archive_origin_bytes).hexdigest(),
                    **{name + "_sha256": hashlib.sha256(data).hexdigest()
                       for name, data in (("object", object_bytes), ("image", image_bytes),
                                          ("report", report_bytes), ("edge_plan", edge_plan_bytes),
                                          ("requested_ir", o2_inputs["requested_ir"]),
                                          ("optimized_ir", o2_inputs["optimized_ir"]),
                                          ("prepared_ir", prepared_ir_bytes))},
                }
                if o2_predicate_proof != expected:
                    raise ValueError("incomplete selected O2 predicate proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder O2 original predicate proof failed: {error}") from error
        if args.builder_archive_decoder_linkage:
            from cff_builder_archive_decoder_linkage import (ARCHIVE_DECODER_CALLEES,
                verify_builder_archive_decoder_linkage)

            try:
                decoder_codes = read_archive_decoder_codes(
                    args.objdump, args.image, ARCHIVE_DECODER_CALLEES)
                archive_decoder_linkage_proof = verify_builder_archive_decoder_linkage(
                    args.builder_object.read_bytes(), args.image.read_bytes(),
                    args.report.read_bytes(), decoder_codes)
                expected = {
                    "object_sha256": hashlib.sha256(args.builder_object.read_bytes()).hexdigest(),
                    "image_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
                    "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
                }
                if (type(archive_decoder_linkage_proof) is not dict or
                        any(archive_decoder_linkage_proof.get(name) is not True for name in
                            ("verified", "decoder_linkage_verified", "require_to_acquire_verified",
                             "acquire_to_children_verified", "argument_chain_verified")) or
                        any(archive_decoder_linkage_proof.get(name) is not False for name in
                            ("decoder_effect_verified", "cache_effect_verified",
                             "platform_crypto_verified",
                             "acquire_inter_state_reachability_verified")) or
                        any(archive_decoder_linkage_proof.get(name) != digest
                            for name, digest in expected.items())):
                    raise ValueError("incomplete archive decoder linkage proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder archive decoder linkage proof failed: {error}") from error
        if args.builder_archive_first_use_arm:
            from cff_builder_archive_first_use import verify_builder_archive_first_use

            try:
                object_bytes = args.builder_object.read_bytes()
                image_bytes = args.image.read_bytes()
                report_bytes = args.report.read_bytes()
                archive_first_use_proof = verify_builder_archive_first_use(
                    object_bytes, image_bytes, report_bytes, decoder_codes)
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
                if archive_first_use_proof != expected:
                    raise ValueError("incomplete conditional archive first-use proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder archive first-use arm proof failed: {error}") from error
        if args.builder_archive_entry_route:
            from cff_builder_archive_entry_route import verify_builder_archive_entry_route

            try:
                object_bytes = args.builder_object.read_bytes()
                image_bytes = args.image.read_bytes()
                report_bytes = args.report.read_bytes()
                archive_entry_route_proof = verify_builder_archive_entry_route(
                    object_bytes, image_bytes, report_bytes, decoder_codes,
                    archive_decoder_linkage_proof, archive_first_use_proof)
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
                    "scope": "selected-archive-entry-success-to-first-use-win64-v1",
                    "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
                    "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
                    "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
                }
                if archive_entry_route_proof != expected:
                    raise ValueError("incomplete archive entry success-route proof")
            except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
                raise SystemExit(f"builder archive entry route proof failed: {error}") from error
    if args.output is not None:
        final_rows = []
        for row in report["functions"]:
            final = dict(row)
            final["transform_status"] = row["status"]
            if row["selected"] and "runtime_contribution" in final:
                final["runtime_contribution"] = dict(final["runtime_contribution"])
                applied = next(item["applied"] for item in row["components"] if item["component"] == "runtime-contribution")
                final["runtime_contribution"]["final_query_presence_verified"] = bool(applied)
                if row["function"] in joint_machine:
                    final["runtime_contribution"].update(joint_machine[row["function"]])
                if row["function"] in original_edges:
                    final["runtime_contribution"]["original_edge_machine"] = original_edges[row["function"]]
            final["final_binary_verified"] = bool(row["selected"])
            final["decision_flow_verified"] = bool(
                row["selected"] and row.get("coverage_kind") in
                ("decision-flow", "region-decision-flow")
            )
            if row["selected"] and "hybrid_eh" in final:
                final["hybrid_eh"]["final_normal_dispatch_presence_verified"] = True
            if row["selected"] and "components" in final:
                for component in final["components"]:
                    component["final_presence_verified"] = bool(
                        component["applied"] and component["component"] in
                        {"cfg", "integer-literals", "internal-calls", "decoy-transitions",
                         "opaque-choices", "reachable-junk", "bogus-clones", "bogus-synthesis",
                         "comparison-constants", "constant-archive", "reference-routes", "import-routes", "call-frames", "external-calls", "call-preparation", "indexed-locals", "path-fold"})
                    component["individual_sites_verified"] = False
            if row["selected"]:
                final["status"] = "final-binary-verified"
            final_rows.append(final)
        result = {
            "image": str(args.image),
            "image_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
            "input_report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
            "strategy": report["strategy"],
            "verification_scope": "function-shape-and-component-presence",
            "functions": final_rows,
        }
        if owner_proof is not None: result["owner_readers"] = owner_proof
        if creator_proof is not None: result["owner_creators"] = creator_proof
        if parent_callback_proof is not None:
            result["parent_callback"] = parent_callback_proof
        if outer_builder_proof is not None:
            result["outer_builder_consistency"] = outer_builder_proof
        if builder_proof is not None:
            result["builder_consistency"] = {
                "verified": True,
                "scope": builder_profile,
                "receipt_sha256": hashlib.sha256(builder_receipt_bytes).hexdigest()}
        if subject_proof is not None:
            result["builder_subjects"] = subject_proof
        if entry_state_proof is not None:
            result["builder_entry_states"] = entry_state_proof
        if local_callee_proof is not None:
            result["builder_local_callees"] = local_callee_proof
        if helper_argument_proof is not None:
            result["builder_helper_arguments"] = helper_argument_proof
        if binding_effect_proof is not None:
            result["builder_binding_status_effects"] = binding_effect_proof
        if context_availability_proof is not None:
            result["builder_context_availability_effect"] = context_availability_proof
        if bound_call_proof is not None:
            result["builder_bound_call"] = bound_call_proof
        if retain_local_proof is not None:
            result["builder_retain_local"] = retain_local_proof
        if invoke_local_proof is not None:
            result["builder_invoke_local"] = invoke_local_proof
        if predicate_proof is not None:
            result["builder_original_predicates"] = predicate_proof
        if archive_publication_proof is not None:
            result["builder_archive_publication"] = archive_publication_proof
        if archive_decoder_linkage_proof is not None:
            result["builder_archive_decoder_linkage"] = archive_decoder_linkage_proof
        if archive_first_use_proof is not None:
            result["builder_archive_first_use_arm"] = archive_first_use_proof
        if archive_entry_route_proof is not None:
            result["builder_archive_entry_route"] = archive_entry_route_proof
        if o2_predicate_proof is not None:
            result["builder_o2_original_predicates"] = o2_predicate_proof
        if replay_proof is not None:
            result["builder_replay"] = replay_proof
        if archive_origin_proof is not None:
            result["archive_origin"] = archive_origin_proof
        if o2_proof is not None:
            result["builder_o2_predecessor"] = o2_proof
        post_inputs = (args.post_release_report, args.post_release_plan, args.post_child_image,
            args.post_child_final, args.post_child_raw, args.post_private, args.post_scoped)
        mixed_join = args.post_join_mixed_plan is not None or args.post_join_material is not None
        if mixed_join and (not args.post_join_mixed_plan or not args.post_join_material or not all(post_inputs)):
            raise SystemExit("mixed POST final join needs its frozen plan, material and all role inputs")
        if any(post_inputs):
            if not all(post_inputs) or owner_proof is None or "post_role_flow" not in report:
                raise SystemExit("POST role join needs all parent and child release inputs")
            from post_role_join import verify_post_mixed_role_join, verify_post_role_join
            try:
                inputs = (args.report.read_bytes(), result, owner_plan, args.image.read_bytes(),
                    args.post_release_report.read_bytes(), args.post_release_plan.read_bytes(),
                    args.post_child_image.read_bytes(), args.post_child_final.read_bytes(),
                    args.post_child_raw.read_bytes(), args.post_private.read_bytes(), args.post_scoped.read_bytes())
                result["post_role_join"] = (verify_post_mixed_role_join(*inputs,
                    args.post_join_material.read_bytes(), args.post_join_mixed_plan.read_bytes()) if mixed_join
                    else verify_post_role_join(*inputs))
            except (OSError, ValueError, KeyError, TypeError) as error:
                raise SystemExit(f"POST role final join failed: {error}") from error
        if builder_receipt_bytes is not None:
            try:
                if args.builder_receipt.read_bytes() != builder_receipt_bytes:
                    raise ValueError("frozen receipt changed during finalization")
                final_inputs = read_builder_inputs(args, mixed_post)
                verify_receipt(builder_receipt_bytes, final_inputs, profile=builder_profile)
                if (result["image_sha256"] != hashlib.sha256(final_inputs["image"]).hexdigest() or
                        result["input_report_sha256"] != hashlib.sha256(final_inputs["report"]).hexdigest()):
                    raise ValueError("final report identity changed during finalization")
            except (OSError, ValueError) as error:
                raise SystemExit(f"builder receipt verification failed: {error}") from error
        if archive_origin_bytes is not None:
            try:
                if args.archive_origin_record.read_bytes() != archive_origin_bytes:
                    raise ValueError("fixed archive record changed during finalization")
                current = {role: path.read_bytes()
                           for role, path in archive_origin_paths.items()}
                if current != archive_origin_inputs:
                    raise ValueError("archive inputs changed during finalization")
                verify_archive_origin_record(archive_origin_bytes, current)
            except (OSError, ValueError) as error:
                raise SystemExit(f"archive origin proof failed: {error}") from error
        if o2_record_bytes is not None:
            try:
                if args.builder_o2_predecessor_record.read_bytes() != o2_record_bytes or \
                        {role: path.read_bytes() for role, path in o2_paths.items()} != o2_inputs:
                    raise ValueError("fixed O2 predecessor inputs changed during finalization")
            except (OSError, ValueError) as error:
                raise SystemExit(f"builder O2 predecessor proof failed: {error}") from error
        if outer_builder_receipt_bytes is not None:
            try:
                if args.outer_builder_receipt.read_bytes() != outer_builder_receipt_bytes:
                    raise ValueError("frozen outer receipt changed during finalization")
                final_outer_inputs = {role: path.read_bytes()
                                      for role, path in outer_builder_paths.items()}
                final_outer_inputs["replay_record"] = args.outer_builder_record.read_bytes()
                verify_receipt(outer_builder_receipt_bytes, final_outer_inputs,
                               profile=OUTER_REPLAY_PROFILE)
                if final_outer_inputs != outer_builder_inputs or (
                        result["image_sha256"] != hashlib.sha256(final_outer_inputs["image"]).hexdigest() or
                        result["input_report_sha256"] != hashlib.sha256(final_outer_inputs["report"]).hexdigest()):
                    raise ValueError("outer builder inputs changed during finalization")
            except (OSError, ValueError) as error:
                raise SystemExit(f"outer builder consistency failed: {error}") from error
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        temporary.replace(args.output)


if __name__ == "__main__":
    main()
