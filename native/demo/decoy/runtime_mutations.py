"""Decoy event faults in LLVM-valid emitted IR; no build proof is rerun."""

import re

from release_flow_mutations import _function, _replace, _return_true, runtime_mutations


def mutations(source):
    for name, text, mode, _ in runtime_mutations(source):
        yield "real-" + name, text, mode, 101
    forced = source
    for owner in ("pass_environment_gate", "prepare_support", "support_is_ready"):
        forced = _return_true(forced, owner)
    yield "force-denied-flow", forced, "forged-denied", 101
    for role, owner in (("initialize", "initialize_decoy"), ("selection", "advance_decoy_selection"),
                        ("preparation", "advance_decoy_preparation"), ("release", "release_decoy")):
        span = _function(source, owner)
        lines = span[2].splitlines(keepends=True)
        stores = [index for index, line in enumerate(lines) if "store volatile i32" in line and "!pyobf.path-fold.bound" in line]
        currents = [index for index, line in enumerate(lines) if "load volatile i32" in line and "!pyobf.path-fold.state" in line]
        if len(stores) != 8 or len(currents) != 1:
            raise AssertionError("decoy owner lost its single eight-lane event")
        yield "decoy-skip-" + role, _replace(source, span, "".join(line for index, line in enumerate(lines) if index not in stores)), "decoy", -9
        current = currents[0]
        original = re.search(r"(%[-\w.$]+) = load volatile i32", lines[current])[1]
        changed = list(lines)
        changed[current] = lines[current].replace(original + " =", "%pyobf.decoy.attack.state =", 1)
        changed.insert(current + 1, f"  {original} = xor i32 %pyobf.decoy.attack.state, 1\n")
        yield "decoy-wrong-state-" + role, _replace(source, span, "".join(changed)), "decoy", -9
        if role != "initialize":
            event = "".join(lines[current:stores[-1] + 1])
            names = sorted(set(re.findall(r"(?m)^\s*(%[-\w.$]+) = ", event)))
            renamed = {value: "%pyobf.decoy.attack.duplicate." + str(index) for index, value in enumerate(names)}
            duplicate = re.sub(r"%[-\w.$]+", lambda match: renamed.get(match[0], match[0]), event)
            changed = lines[:stores[-1] + 1] + [duplicate] + lines[stores[-1] + 1:]
            yield "decoy-duplicate-" + role, _replace(source, span, "".join(changed)), "decoy", -9
    for owner in ("initialize_decoy", "advance_decoy_selection", "reconstruct_decoy_key"):
        yield "decoy-force-" + owner, _return_true(source, owner), "decoy", -9
    failed_hash = next(text for name, text, _, _ in runtime_mutations(source) if name == "force-failed-hash-result")
    yield "decoy-force-failed-hash", failed_hash, "decoy-failed-hash", -9
    for owner, target, mode, expected in (("release_and_load_payload", "decrypt_payload", "corrupt-real", -5),
                                          ("release_decoy", "decrypt_aead", "decoy-corrupt", -9)):
        span = _function(source, owner)
        call = re.search(r"(?m)^(\s*)(%[-\w.$]+) = ((?:tail )?call [^\n]*@[^\n(]*" + target + r"[^\n(]*\([^\n]*)$", span[2])
        if call is None: raise AssertionError("release fault lost its actual AEAD request")
        patched = call[1] + "%pyobf.attack.auth = " + call[3] + "\n  " + call[2] + " = or i1 true, false"
        body = span[2][:call.start()] + patched + span[2][call.end():]
        yield "force-auth-" + target, _replace(source, span, body), mode, expected
