"""Valid-IR post-emission faults; runtime tests deliberately bypass the build proof."""

import re


def _function(source, fragment):
    matches = list(re.finditer(r"(?m)^define [^\n]*@[^\n(]*" + re.escape(fragment) + r"[^\n(]*\([^\n]*\)[^\n]*\{", source))
    if len(matches) != 1: raise AssertionError("release fault owner is missing or ambiguous")
    start = matches[0].start()
    end = source.index("\n}", matches[0].end()) + 2
    return start, end, source[start:end]


def _replace(source, span, body):
    return source[:span[0]] + body + source[span[1]:]


def _return_true(source, fragment):
    span = _function(source, fragment)
    return _replace(source, span, span[2][:span[2].index("{") + 1] + "\n  ret i1 true\n}")


def runtime_mutations(source):
    for role, name in (("initialize", "initialize_session"), ("environment", "pass_environment_gate"),
                       ("support", "dispatch_lifecycle"), ("release", "release_and_load_payload")):
        span = _function(source, name)
        lines = span[2].splitlines(keepends=True)
        stores = [index for index, line in enumerate(lines) if "store volatile i32" in line and "!pyobf.path-fold.bound" in line]
        currents = [index for index, line in enumerate(lines) if "load volatile i32" in line and "!pyobf.path-fold.state" in line]
        if len(stores) != 8 or len(currents) != 1: raise AssertionError("release fault lost its single eight-lane event")
        changed = [line for index, line in enumerate(lines) if index not in stores]
        yield "skip-" + role, _replace(source, span, "".join(changed)), "root", -4
        current = currents[0]
        original = re.search(r"(%[-\w.$]+) = load volatile i32", lines[current])[1]
        changed = list(lines)
        changed[current] = lines[current].replace(original + " =", "%pyobf.attack.state =", 1)
        changed.insert(current + 1, f"  {original} = xor i32 %pyobf.attack.state, 1\n")
        yield "wrong-state-" + role, _replace(source, span, "".join(changed)), "root", -4
        if role != "initialize":
            event = "".join(lines[current:stores[-1] + 1])
            names = set(re.findall(r"(?m)^\s*(%[-\w.$]+) = ", event))
            renamed = {value: "%pyobf.attack.duplicate." + str(index) for index, value in enumerate(sorted(names))}
            duplicate = re.sub(r"%[-\w.$]+", lambda match: renamed.get(match[0], match[0]), event)
            changed = lines[:stores[-1] + 1] + [duplicate] + lines[stores[-1] + 1:]
            yield "duplicate-" + role, _replace(source, span, "".join(changed)), "root", -4
    yield "force-support-result", _return_true(source, "prepare_support"), "root", -7
    forced = _return_true(_return_true(source, "prepare_support"), "support_is_ready")
    yield "force-both-support-results", forced, "root", -4
    yield "force-key-result", _return_true(source, "reconstruct_payload_key"), "root", -4
    span = _function(source, "expand_release_key")
    call = re.search(r"(?m)^(\s*)(%[-\w.$]+) = (call [^\n]*@[^\n(]*hash_sha256[^\n(]*\([^\n]*)$", span[2])
    if call is None: raise AssertionError("release fault lost its actual hash request")
    patched = (call[1] + "%pyobf.attack.hash = " + call[3] + "\n  " + call[2] + " = or i1 true, false")
    body = span[2][:call.start()] + patched + span[2][call.end():]
    yield "force-failed-hash-result", _replace(source, span, body), "failed-hash", -4
