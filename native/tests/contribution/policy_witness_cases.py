"""Actual-image and independent private-input refusals for schema4 final evidence."""

import copy
import hashlib
import json
import re
import struct
import subprocess

from cff_joint_machine_evidence import _instructions
from linked_machine_mutations import _replace
from pe_layout import parse_image


def positive(checker, binary, report, private, baseline, directory, run, joint=False):
    witness = directory / (binary.stem + ".policy.final.json")
    command = [*checker, binary, report, "--contribution-input", private, "--output", witness]
    run(command)
    if json.loads(witness.read_text()) != json.loads(baseline.read_text()):
        raise AssertionError("optional policy input changed the existing final report")
    if joint:
        diagnostic = directory / (binary.stem + ".policy.joint.final.json")
        run([*checker, binary, report, "--contribution-input", private,
             "--check-joint-caller-flow", "--output", diagnostic])
        proof = next(row["runtime_contribution"] for row in json.loads(diagnostic.read_text())["functions"]
                     if row.get("function") == "mixed_site_body")
        if (proof.get("joint_caller_pointer_provenance_verified") is not False or
                proof.get("cross_provider_owner_binding_verified") is not False or
                proof.get("individual_sites_verified") is not False):
            raise AssertionError("policy input promoted an unproved machine binding")
    print("independent schema4 policy + actual linked image pass:", binary.name)


def negatives(checker, binary, report, private, directory, objdump, run,
              opt, plugin, configuration, requests, requested):
    document = json.loads(report.read_text())
    raw = private.read_bytes()

    def refused(label, image=binary, candidate_report=report, candidate_policy=private, reason="source-mixed private policy"):
        final = directory / f"policy-{label}.final.json"
        result = run([*checker, image, candidate_report, "--contribution-input", candidate_policy,
                      "--output", final], succeeds=False)
        if final.exists() or reason not in result.stderr:
            raise AssertionError(f"independent policy accepted {label}: {result.stderr}")
        print("independent policy refused:", label)

    refused("missing", candidate_policy=directory / "absent.private.json", reason="No such file")
    code = subprocess.check_output([str(objdump), "-d", "--disassemble-symbols=mixed_site_body",
                                    str(binary)], text=True, timeout=20).lower()
    image = binary.read_bytes()
    stores = [item for item in _instructions(code, image, "mixed_site_body")
              if item.opcode == "movl" and item.operands == ("$0xd", "0x28(%rsp)")]
    if len(stores) != 1 or stores[0].raw[-4:] != struct.pack("<I", 13):
        raise AssertionError("paired PE/report fixture lost the unique owned source immediate")
    changed_image = directory / "policy-paired-word.exe"
    changed_image.write_bytes(_replace(image, parse_image(image), stores[0],
                                       stores[0].raw[:-4] + struct.pack("<I", 41)))
    changed_report = copy.deepcopy(document)
    proof = next(row["runtime_contribution"] for row in changed_report["functions"]
                 if row.get("function") == "mixed_site_body")
    proof["sites"][0]["sources"][0]["word_label"] = 41
    paired = directory / "policy-paired-word.coverage.json"
    paired.write_text(json.dumps(changed_report))
    old_final = directory / "policy-paired-word.unwitnessed.final.json"
    run([*checker, changed_image, paired, "--output", old_final])
    if not old_final.exists():
        raise AssertionError("paired PE/report mutation no longer reproduces the original false accept")
    refused("paired-word", changed_image, paired, reason="projection differs")
    reused = directory / "policy-reused.final.json"
    run([*checker, binary, report, "--contribution-input", private, "--output", reused])
    if not reused.exists():
        raise AssertionError("reused-output fixture lacks its prior successful final report")
    second = run([*checker, changed_image, paired, "--contribution-input", private,
                  "--output", reused], succeeds=False)
    if reused.exists() or "projection differs" not in second.stderr:
        raise AssertionError(f"stale final output survived policy refusal: {second.stderr}")
    print("independent policy cleared stale final output before refusal")
    for label, path in (("report", report), ("private", private), ("image", binary)):
        before = path.read_bytes()
        denied = run([*checker, binary, report, "--contribution-input", private,
                      "--output", path], succeeds=False)
        if path.read_bytes() != before or "final output aliases an input" not in denied.stderr:
            raise AssertionError(f"policy output alias damaged {label}: {denied.stderr}")
        print("independent policy refused output alias:", label)
    temporary_output = directory / "policy-temporary-alias.final.json"
    temporary_alias = temporary_output.with_name(temporary_output.name + ".tmp")
    temporary_alias.write_bytes(raw)
    denied = run([*checker, binary, report, "--contribution-input", temporary_alias,
                  "--output", temporary_output], succeeds=False)
    if (temporary_alias.read_bytes() != raw or temporary_output.exists() or
            "final output aliases an input" not in denied.stderr):
        raise AssertionError(f"policy temporary-file alias damaged private input: {denied.stderr}")
    print("independent policy refused temporary-file input alias")

    def changed_report_case(label, mutate, reason):
        changed = copy.deepcopy(document)
        proof = next(row["runtime_contribution"] for row in changed["functions"]
                     if row.get("function") == "mixed_site_body")
        mutate(proof)
        path = directory / f"policy-{label}.coverage.json"
        path.write_text(json.dumps(changed))
        refused(label, candidate_report=path, reason=reason)

    changed_report_case("source-id", lambda proof: proof["sites"][0]["sources"][0].update(id="wrong-id"),
                        "projection differs")
    changed_report_case("source-order", lambda proof: proof["sites"][0]["sources"].reverse(),
                        "projection differs")
    changed_report_case("group-minimum", lambda proof: proof["sites"][0]["groups"][0].update(minimum=1),
                        "projection differs")
    changed_report_case("domain-name", lambda proof: proof["sites"][0].update(mixing_domain="forged-domain"),
                        "projection differs")
    changed_report_case("domain-tag", lambda proof: proof["sites"][0].update(
        mixing_domain_tag=proof["sites"][0]["mixing_domain_tag"] ^ 1), "projection differs")
    changed_report_case("report-sha", lambda proof: proof.update(private_input_sha256="0" * 64),
                        "raw input SHA-256 differs")

    def changed_policy_case(label, mutate, reason):
        changed = json.loads(raw)
        mutate(changed)
        policy_bytes = json.dumps(changed).encode()
        policy = directory / f"policy-{label}.private.json"
        policy.write_bytes(policy_bytes)
        forged = copy.deepcopy(document)
        proof = next(row["runtime_contribution"] for row in forged["functions"]
                     if row.get("function") == "mixed_site_body")
        proof["private_input_sha256"] = hashlib.sha256(policy_bytes).hexdigest()
        coverage = directory / f"policy-{label}.coverage.json"
        coverage.write_text(json.dumps(forged))
        refused(label, candidate_report=coverage, candidate_policy=policy, reason=reason)

    changed_policy_case("wrong-owner", lambda policy: (
        policy["owners"].update(other_owner=policy["owners"].pop("mixed_site_body")),
        policy["bindings"].update(other_owner=policy["bindings"].pop("mixed_site_body"))),
        "private owner differs")
    changed_policy_case("wrong-schema", lambda policy: policy.update(
        schema_version=3, provider="site-mixed-v1"), "unsupported schema/provider")
    changed_policy_case("wrong-source", lambda policy: policy["sources"][0].update(word_label=41),
                        "projection differs")
    changed_policy_case("third-site", lambda policy: policy["bindings"]["mixed_site_body"]["sites"].update(
        {"705": copy.deepcopy(policy["bindings"]["mixed_site_body"]["sites"]["703"])}),
        "one or two explicit sites")
    encoded = raw.decode("utf-8")
    match = re.search(r'"701"\s*:\s*\{', encoded)
    if match is None:
        raise AssertionError("duplicate-key fixture lost the original site rule")
    duplicate = (encoded[:match.start()] + '"\\u0037\\u0030\\u0031": null, ' +
                 encoded[match.start():]).encode()
    duplicate_path = directory / "policy-duplicate.private.json"
    duplicate_path.write_bytes(duplicate)
    refused("unicode-duplicate-key", candidate_policy=duplicate_path,
            reason="duplicate JSON object key")

    colliding = json.loads(raw)
    rules = colliding["bindings"]["mixed_site_body"]["sites"]
    rules["701"]["mixing_domain"] = "mixmoyil4"
    rules["703"]["mixing_domain"] = "mix1d7fp0r"
    collision_bytes = json.dumps(colliding).encode()
    collision_policy = directory / "policy-domain-collision.private.json"
    collision_policy.write_bytes(collision_bytes)
    forged = copy.deepcopy(document)
    proof = next(row["runtime_contribution"] for row in forged["functions"]
                 if row.get("function") == "mixed_site_body")
    proof["private_input_sha256"] = hashlib.sha256(collision_bytes).hexdigest()
    for site, name in zip(proof["sites"], ("mixmoyil4", "mix1d7fp0r")):
        site["mixing_domain"] = name
        site["mixing_domain_tag"] = 2819301039
    collision_report = directory / "policy-domain-collision.coverage.json"
    collision_report.write_text(json.dumps(forged))
    unwitnessed = directory / "policy-domain-collision.unwitnessed.final.json"
    run([*checker, binary, collision_report, "--output", unwitnessed])
    if not unwitnessed.exists():
        raise AssertionError("domain-collision report did not reach the new policy gate")
    refused("domain-collision", candidate_report=collision_report,
            candidate_policy=collision_policy, reason="mixing domain identity collision")
    protected = directory / "policy-domain-collision.protected.ll"
    compiler = run([opt, f"-load-pass-plugin={plugin}", f"-pyobf-cff-config={configuration}",
                    "-passes=pyobf-native-cff", f"-pyobf-cff-requests-input={requests}",
                    f"-pyobf-cff-contribution-input={collision_policy}", "-S", requested,
                    "-o", protected], succeeds=False)
    if protected.exists() or "mixing domain identity collision" not in compiler.stderr:
        raise AssertionError(f"native compiler accepted colliding private domains: {compiler.stderr}")
    print("native compiler and independent policy both refuse colliding domain identities")
