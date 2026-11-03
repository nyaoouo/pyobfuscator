"""Independent configured subsets and malformed grouped-source controls."""
import copy
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from pe_layout import parse_image, rva_section

from cff_build import run
from cff_contribution_groups import check_contribution_groups
from cff_grouped_owned_flow import Instruction, checked_stack_effect, dispatcher_state_slot, reachable_stack_depths
from edge_policies import function_body


def configure_groups(private):
    data = json.loads(private.read_text())
    data["schema_version"] = 2; del data["source"]
    data["sources"] = [{"id": name, "word_label": label, "group": "bootstrap"}
        for name, label in (("alpha", 17), ("beta", 29), ("gamma", 41))]
    data["bindings"] = {}
    for index, owner in enumerate(data["owners"]):
        data["bindings"][owner] = {"default": {"sources": ["alpha", "beta"] if index % 2 == 0 else ["gamma", "alpha", "beta"],
            "mixing_domain": "material:" + owner, "groups": [{"id": "bootstrap", "minimum": 1}]}}
    data["bindings"]["contribution_compute"]["sites"] = {
        "101": {"sources": ["gamma"], "mixing_domain": "entry", "groups": [{"id": "bootstrap", "minimum": 1}]},
        "303": {"sources": ["beta", "alpha"], "mixing_domain": "exit", "groups": [{"id": "bootstrap", "minimum": 2}]}}
    private.write_text(json.dumps(data))


def group_acceptance(args, directory, transform, private, protected, rows):
    data = json.loads(private.read_text())
    catalog = {item["id"]: item for item in data["sources"]}
    for row in rows:
        if row["function"] not in data["bindings"]: continue
        proof = row["runtime_contribution"]
        count = next(item["applied"] for item in row["components"] if item["component"] == "runtime-contribution")
        check_contribution_groups(proof, count, row["function"])
        owner = data["bindings"][row["function"]]
        body = function_body(protected.read_text(), row["function"])
        expected_queries = 0
        for site in proof["sites"]:
            rule = owner.get("sites", {}).get(str(site["label"]), owner.get("default"))
            if rule is None or site["mixing_domain"] != rule["mixing_domain"]:
                raise AssertionError("actual retained point has no matching configured binding")
            expected = [(name, catalog[name]["word_label"], 1) for name in rule["sources"]]
            actual = [(source["id"], source["word_label"], source["encoding"]) for source in site["sources"]]
            if actual != expected: raise AssertionError("actual ordered subset differs from independent input rule")
            expected_queries += len(expected)
        if len(proof["sites"]) != count or body.count("call i32 @pyobf_native_contribution_word_v1") != expected_queries:
            raise AssertionError("bound sites were confused with actual acquisition calls")
    variants = []
    def change(operation, reason):
        candidate = copy.deepcopy(data); operation(candidate); variants.append((candidate, reason))
    change(lambda d: d["sources"][0].update(provider="missing"), "not registered")
    change(lambda d: d["sources"][0].update(provider_version=2), "not registered")
    change(lambda d: d["sources"][1].update(word_label=17), "aliased word label")
    change(lambda d: d["sources"][1].update(id="alpha"), "duplicate source")
    change(lambda d: d["bindings"]["contribution_compute"]["default"].update(sources=["absent"]), "unknown or duplicate source")
    change(lambda d: d["bindings"]["contribution_compute"]["default"].update(sources=["alpha", "alpha"]), "unknown or duplicate source")
    change(lambda d: d["bindings"]["contribution_compute"]["default"].update(sources=[]), "invalid source subset")
    change(lambda d: d["bindings"]["contribution_compute"]["default"]["groups"][0].update(minimum=3), "required source group")
    change(lambda d: d["bindings"]["contribution_compute"]["default"]["groups"][0].update(independent_evidence=True), "required source group")
    change(lambda d: d["bindings"]["contribution_compute"]["default"].update(mixing_domain=""), "bounded identity")
    change(lambda d: d["bindings"]["contribution_compute"]["sites"].update({"999999": d["bindings"]["contribution_compute"]["default"]}), "point label was not retained")
    for index, (candidate, reason) in enumerate(variants):
        path, output = directory / f"group-input-{index}.json", directory / f"group-input-{index}.ll"
        path.write_text(json.dumps(candidate))
        result = run([*transform, f"-pyobf-cff-contribution-input={path}", "-o", output], succeeds=False)
        if reason not in result.stderr: raise AssertionError(f"group refusal failed elsewhere: {reason}; {result.stderr[:700]}")
        if output.exists() and output.stat().st_size: raise AssertionError("invalid source group emitted usable IR")
    encoded = private.read_text()
    rule = '"101": ' + json.dumps(data["bindings"]["contribution_compute"]["sites"]["101"])
    if encoded.count(rule) != 1: raise AssertionError("duplicate-key control lost its exact private site rule")
    for label, prefix in (("plain", '"101": null, '),
                          ("escaped", r'"\u0031\u0030\u0031": null, ')):
        path, output = directory / f"group-duplicate-key-{label}.json", directory / f"group-duplicate-key-{label}.ll"
        path.write_text(encoded.replace(rule, prefix + rule, 1))
        result = run([*transform, f"-pyobf-cff-contribution-input={path}", "-o", output], succeeds=False)
        if "duplicate JSON object key" not in result.stderr or output.exists():
            raise AssertionError(f"duplicate private rule escaped raw input gate: {label}: {result.stderr[:700]}")
    row = next(row for row in rows if row["function"] == "contribution_compute")
    count = next(item["applied"] for item in row["components"] if item["component"] == "runtime-contribution")
    config_arg = next(value for value in transform if str(value).startswith("-pyobf-cff-config="))
    recipe = json.loads(Path(str(config_arg).split("=", 1)[1]).read_text())
    # Keep the tested structural contract while tightening only the query budget.
    recipe["functions"]["contribution_compute"].setdefault("budgets", {})["max_contribution_sites"] = count
    budget = directory / "group-weighted-budget.json"; budget.write_text(json.dumps(recipe))
    command = [f"-pyobf-cff-config={budget}" if value == config_arg else value for value in transform]
    result = run([*command, f"-pyobf-cff-contribution-input={private}", "-o", directory / "group-weighted-budget.ll"], succeeds=False)
    if "queries exceed max_contribution_sites" not in result.stderr:
        raise AssertionError("source acquisitions did not consume the query budget independently of site count")
    mutations = []
    for field, value in (("query_count", 0), ("sites", []), ("source_subset_contract_verified", False)):
        proof = copy.deepcopy(row["runtime_contribution"]); proof[field] = value; mutations.append(proof)
    for field, value in (("class", "independent-evidence"), ("sharing", "owner-independent"), ("encoding", 0), ("use", "observation-only")):
        proof = copy.deepcopy(row["runtime_contribution"]); proof["sites"][0]["sources"][0][field] = value; mutations.append(proof)
    proof = copy.deepcopy(row["runtime_contribution"]); proof["sites"][0]["sources"].pop(); mutations.append(proof)
    for proof in mutations:
        try: check_contribution_groups(proof, count, row["function"])
        except SystemExit: pass
        else: raise AssertionError("false grouped-source final evidence survived")
    return len(variants) + 1, len(mutations)


def grouped_return_refusals(args, directory, protected, report, checker, build_image, rows, protected_image):
    owner = "contribution_compute"
    proof = next(row["runtime_contribution"] for row in rows if row["function"] == owner)
    site = next(site for site in sorted(proof["sites"], key=lambda item: item["label"] != 202)
                if len(site["sources"]) > 1)
    route_site = next(site for site in sorted(proof["sites"], key=lambda item: item["label"] != 303)
                      if len(site["sources"]) > 1)
    source = site["sources"][0]
    original = protected.read_text()
    body = function_body(original, owner)
    pattern = (rf"(?m)^  (%[\w.]+) = call i32 @pyobf_native_contribution_word_v1\("
               rf"[^\n]*, i32 {site['label']}, i32 {source['word_label']}, [^\n]*\)[^\n]*$")
    matches = list(re.finditer(pattern, body))
    if len(matches) != 1:
        raise AssertionError("grouped member mutation did not find one actual query")
    match = matches[0]
    mutations = (("detached", None),) if args.automatic else (
        ("detached", None), ("zero-factor", "mul"), ("self-xor", "xor"))
    for name, operation in mutations:
        suffix = body[match.end():]
        replacement = "0" if operation is None else f"%grouped.{name.replace('-', '_')}"
        suffix, uses = re.subn(rf"(?<![\w.]){re.escape(match[1])}(?![\w.])", replacement, suffix)
        if uses < 1:
            raise AssertionError("grouped member return had no actual use to detach")
        insertion = "" if operation is None else (f"\n  {replacement} = {operation} i32 {match[1]}, "
                                                       f"{'0' if operation == 'mul' else match[1]}")
        changed_body = body[:match.end()] + insertion + suffix
        if original.count(body) != 1:
            raise AssertionError("grouped owner body is not unique")
        mutant = directory / f"grouped-{name}.ll"
        mutant.write_text(original.replace(body, changed_body, 1))
        binary = build_image(f"grouped-{name}", mutant)
        final = directory / f"grouped-{name}.final.json"
        rejected = run([*checker, binary, report, "--output", final], succeeds=False)
        if "linked image lost grouped owned query return flow" not in rejected.stderr or final.exists():
            raise AssertionError(f"linked grouped {name} return failed outside the return-flow gate: {rejected.stderr[:500]}")
        try:
            result = subprocess.run([binary], capture_output=True, text=True, timeout=4)
            output = result.stdout
        except subprocess.TimeoutExpired as error:
            output = error.stdout or b""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
        if "gate-enter" not in output or "gate-normal-completed" in output:
            raise AssertionError(f"linked grouped {name} child completed after return detachment: {output[:500]}")
        print(f"grouped linked {name}: return gate refused, admitted run did not complete")
    if args.automatic:
        return len(site["sources"]), 1
    assembly = run([args.objdump, "-d", f"--disassemble-symbols={owner}", protected_image]).stdout.lower()
    instructions = []
    for line in assembly.splitlines():
        columns = line.strip().split("\t")
        if len(columns) < 2:
            continue
        match = re.match(r"^([0-9a-f]{8,16}):\s*((?:[0-9a-f]{2}\s*)+)$", columns[0])
        if match is None:
            continue
        instructions.append((int(match[1], 16), bytes.fromhex(match[2]), columns[1].strip(),
                             columns[2].split("#", 1)[0].strip() if len(columns) > 2 else ""))
    site_immediate = f"$0x{route_site['label']:x}, 0x20(%rsp)"
    matching = [index for index, item in enumerate(instructions)
                if item[2] == "movl" and item[3] == site_immediate]
    if len(matching) != len(route_site["sources"]):
        raise AssertionError("branch-skip fixture lost the actual grouped site label")
    first = matching[0]
    previous = next((index for index in range(first - 1, -1, -1)
                     if instructions[index][2].startswith(("j", "ret"))), None)
    if previous is None:
        raise AssertionError("grouped site has no preceding block boundary")
    group_start = instructions[previous + 1][0]
    following = next((item for item in instructions[matching[-1] + 1:]
                      if item[2] in ("jmp", "jmpq")), None)
    if following is None:
        raise AssertionError("grouped site has no direct post-query dispatch")
    target = re.match(r"^0x([0-9a-f]+)", following[3])
    if target is None:
        raise AssertionError("grouped post-query dispatch is not direct")
    bypass_target = int(target[1], 16)
    predecessors = [item for item in instructions if item[2] in ("jmp", "jmpq") and
                    re.match(r"^0x([0-9a-f]+)", item[3]) and
                    int(re.match(r"^0x([0-9a-f]+)", item[3])[1], 16) == group_start]
    if len(predecessors) != 1 or len(predecessors[0][1]) != 5 or predecessors[0][1][0] != 0xe9:
        raise AssertionError("grouped site does not have one patchable direct predecessor")
    jump = predecessors[0]
    original_bytes = protected_image.read_bytes()
    image = parse_image(original_bytes)

    def rel32(instruction, target):
        if len(instruction[1]) != 5 or instruction[1][0] != 0xe9:
            raise AssertionError("selected linked jump is not rel32")
        displacement = target - (instruction[0] + 5)
        if not -(1 << 31) <= displacement < 1 << 31:
            raise AssertionError("linked jump target exceeds rel32")
        return b"\xe9" + displacement.to_bytes(4, "little", signed=True)

    def reject_patched(name, patches, reason):
        changed = bytearray(original_bytes)
        for address, before, after in patches:
            if len(before) != len(after):
                raise AssertionError("linked mutation changed instruction size")
            rva = address - image.preferred_base
            section = rva_section(image, rva, len(before), logical=True)
            offset = section.raw_offset + rva - section.rva
            if original_bytes[offset:offset + len(before)] != before:
                raise AssertionError("linked mutation differs from actual PE bytes")
            changed[offset:offset + len(after)] = after
        binary = directory / f"grouped-{name}.exe"
        binary.write_bytes(changed)
        final = directory / f"grouped-{name}.final.json"
        rejected = run([*checker, binary, report, "--output", final], succeeds=False)
        if reason not in rejected.stderr or final.exists():
            raise AssertionError(f"linked {name} PE retained a grouped final claim: {rejected.stderr[:500]}")
        try:
            result = subprocess.run([binary], capture_output=True, text=True, timeout=4)
            output = result.stdout
        except subprocess.TimeoutExpired as error:
            output = error.stdout or b""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
        if "gate-enter" not in output or "gate-normal-completed" in output:
            raise AssertionError(f"linked {name} PE completed normally: {output[:500]}")
        print(f"grouped linked {name}: {reason}; admitted run did not complete")

    reject_patched("branch-skip", [(jump[0], jump[1], rel32(jump, bypass_target))],
                   "linked image lost grouped owned reachable query groups")
    reject_patched("postquery-retarget", [(following[0], following[1], rel32(following, group_start))],
                   "linked image lost grouped owned dispatcher route")
    dispatcher_compare = next((item for item in instructions if item[0] >= bypass_target and item[2] == "cmpl"), None)
    if dispatcher_compare is None or len(dispatcher_compare[1]) != 5 or dispatcher_compare[1][0] != 0x3d or not dispatcher_compare[3].endswith(", %eax"):
        raise AssertionError("selected dispatcher comparison is not a five-byte immediate test")
    reject_patched("dispatcher-self-compare", [(dispatcher_compare[0], dispatcher_compare[1], b"\x39\xc0\x40\x89\xc0")],
                   "unsupported grouped owned dispatcher pivot")

    count = 6
    if args.optimization == "none":
        repeated = [index for index, item in enumerate(instructions)
                    if item[2] == "movl" and item[3] == f"$0x{site['label']:x}, 0x20(%rsp)"]
        if len(repeated) != len(site["sources"]):
            raise AssertionError("linked loop site lost its repeated member argument stores")
        second = repeated[1]
        refreshed_word = next((item for item in instructions[second + 1:]
                               if item[2] == "movl" and item[3].endswith(", 0x28(%rsp)")), None)
        if refreshed_word is None or len(refreshed_word[1]) < 4:
            raise AssertionError("linked second query has no word-label refresh")
        reject_patched("member-argument-not-refreshed",
                       [(refreshed_word[0], refreshed_word[1], b"\x90" * len(refreshed_word[1]))],
                       "linked image lost grouped owned query state origin")
        state = next((int(match[1], 16) for item in instructions[:first] if item[2] == "movl"
                      if (match := re.fullmatch(r"\$0x[0-9a-f]+, 0x([0-9a-f]+)\(%rsp\)", item[3]))), None)
        if state is None:
            raise AssertionError("linked entry has no anchored state slot")
        entry_end = next((index for index, item in enumerate(instructions) if item[2] in ("jmp", "jmpq")), None)
        entry_write = next((item for item in instructions[:entry_end]
                            if item[2] == "movl" and len(item[1]) == 4 and item[3].endswith("(%rsp)")), None)
        if entry_write is None:
            raise AssertionError("linked entry has no four-byte stack store for RSP controls")
        reject_patched("entry-pop-rsp", [(entry_write[0], entry_write[1], b"\x5c\x0f\x1f\x00")],
                       "unsupported grouped owned stack adjustment")
        reject_patched("entry-xchg-rsp", [(entry_write[0], entry_write[1], b"\x48\x87\xe0\x90")],
                       "unsupported grouped owned stack adjustment")
        esp_write = next((item for item in instructions[:first]
                          if item[2] == "movl" and len(item[1]) == 5 and
                          re.fullmatch(r"\$0x[0-9a-f]+, %e[a-d]x", item[3])), None)
        if esp_write is None:
            raise AssertionError("linked query has no immediate register write for ESP control")
        reject_patched("group-esp-write", [(esp_write[0], esp_write[1], b"\xbc\x00\x00\x00\x00")],
                       "unsupported grouped owned stack adjustment")
        indirect_write = next((item for item in instructions[:first]
                               if item[2] == "movl" and len(item[1]) == 4 and
                               item[3] == "%eax, 0x30(%rsp)"), None)
        if indirect_write is None:
            raise AssertionError("linked query has no stack write for memory-alias control")
        reject_patched("group-indirect-write", [(indirect_write[0], indirect_write[1], b"\x41\x89\x04\x24")],
                       "unsupported grouped owned machine transfer")
        argument_store = next((item for item in instructions[:first]
                               if item[2] == "movl" and len(item[1]) == 8 and item[1][3] == 0x20 and
                               re.fullmatch(r"\$0x[0-9a-f]+, 0x20\(%rsp\)", item[3])), None)
        if argument_store is None:
            raise AssertionError("linked query has no patchable grouped argument store")
        changed_argument = bytearray(argument_store[1]); changed_argument[3] = 0x21
        reject_patched("group-argument-overlap", [(argument_store[0], argument_store[1], bytes(changed_argument))],
                       "linked image lost grouped owned query argument bytes")
        dispatcher_read = next((item for item in instructions
                                if item[0] == bypass_target and item[2] == "movl" and len(item[1]) == 7 and
                                item[3] == f"0x{state:x}(%rsp), %eax"), None)
        if dispatcher_read is None:
            raise AssertionError("linked dispatcher has no patchable state read")
        overlapping_store = b"\x89\x84\x24" + (state + 2).to_bytes(4, "little")
        reject_patched("dispatcher-state-overlap", [(dispatcher_read[0], dispatcher_read[1], overlapping_store)],
                       "linked image lost grouped owned dispatcher state frame")
        # The emitted entry jumps immediately after initialization; exercise its late-write rule directly.
        entry = [Instruction(1, 1, "movl", ("$1", f"0x{state:x}(%rsp)"), ""),
                 Instruction(2, 1, "movq", ("%rax", f"0x{state:x}(%rsp)"), ""),
                 Instruction(3, 1, "jmp", ("0x10",), "0x10")]
        dispatch = [Instruction(0x10, 1, "movl", (f"0x{state:x}(%rsp)", "%eax"), ""),
                    Instruction(0x11, 1, "cmpl", ("$1", "%eax"), ""),
                    Instruction(0x12, 1, "jae", ("0x20",), "0x20")]
        try:
            dispatcher_state_slot([entry, dispatch], owner)
        except SystemExit as error:
            if "entry state frame" not in str(error):
                raise AssertionError(f"late entry overwrite failed at the wrong boundary: {error}") from error
        else:
            raise AssertionError("late entry state overwrite survived bounded proof")
        overlapping_dispatch = [Instruction(0x10, 1, "movl", ("%eax", f"0x{state + 2:x}(%rsp)"), ""),
                                Instruction(0x11, 1, "movl", (f"0x{state:x}(%rsp)", "%eax"), ""),
                                Instruction(0x12, 1, "cmpl", ("$1", "%eax"), ""),
                                Instruction(0x13, 1, "jae", ("0x20",), "0x20")]
        try:
            dispatcher_state_slot([entry[:1] + entry[2:], overlapping_dispatch], owner)
        except SystemExit as error:
            if "dispatcher state frame" not in str(error):
                raise AssertionError(f"partial dispatcher overwrite failed at the wrong boundary: {error}") from error
        else:
            raise AssertionError("partial dispatcher state overwrite survived bounded proof")
        try:
            checked_stack_effect(Instruction(1, 2, "loop", ("0x10",), "0x10"), owner)
        except SystemExit as error:
            if "machine transfer" not in str(error):
                raise AssertionError(f"unmodeled control transfer failed at the wrong boundary: {error}") from error
        else:
            raise AssertionError("unmodeled control transfer survived bounded proof")
        transient = [[Instruction(1, 1, "subq", ("$0x98", "%rsp"), ""),
                      Instruction(2, 1, "jmp", ("0x10",), "0x10")],
                     [Instruction(0x10, 1, "addq", ("$0x9c", "%rsp"), ""),
                      Instruction(0x11, 1, "pushq", ("%rax",), ""),
                      Instruction(0x12, 1, "subq", ("$0x94", "%rsp"), ""),
                      Instruction(0x13, 1, "jmp", ("0x20",), "0x20")],
                     [Instruction(0x20, 1, "retq", (), "")]]
        try:
            reachable_stack_depths(transient, owner)
        except SystemExit as error:
            if "transient stack adjustment" not in str(error):
                raise AssertionError(f"transient stack alias failed at the wrong boundary: {error}") from error
        else:
            raise AssertionError("transient stack alias survived bounded proof")
        count += 7
        decoy = 0x80
        if state is None or state < 0x80 or f"0x{decoy:x}(%rsp)" in assembly:
            raise AssertionError("linked decoy slot is not a free bounded stack slot")
        patches = []
        for grouped in proof["sites"]:
            stores = [index for index, item in enumerate(instructions)
                      if item[2] == "movl" and item[3] == f"$0x{grouped['label']:x}, 0x20(%rsp)"]
            if len(stores) != len(grouped["sources"]):
                raise AssertionError("decoy-slot fixture lost a grouped site")
            prior = next((index for index in range(stores[0] - 1, -1, -1)
                          if instructions[index][2].startswith(("j", "ret"))), None)
            if prior is None:
                raise AssertionError("decoy-slot fixture lost group start")
            for item in instructions[prior + 1:]:
                if item[0] >= bypass_target and item[0] > instructions[stores[-1]][0]:
                    break
                if item[2].startswith(("j", "ret")) and item[0] > instructions[stores[-1]][0]:
                    break
                if item[2] != "movl" or f"0x{state:x}(%rsp)" not in item[3]:
                    continue
                encoded = state.to_bytes(4, "little")
                position = item[1].find(encoded)
                if position < 0 or item[1].find(encoded, position + 1) >= 0:
                    raise AssertionError("decoy state displacement is not unique")
                changed = bytearray(item[1]); changed[position:position + 4] = decoy.to_bytes(4, "little")
                patches.append((item[0], item[1], bytes(changed)))
        if len(patches) < len(proof["sites"]) * 2:
            raise AssertionError("decoy mutation did not redirect every group source and sink")
        reject_patched("decoy-state", patches, "linked image lost grouped owned query state origin")
        count += 1
    return len(site["sources"]), count
