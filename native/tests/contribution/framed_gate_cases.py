"""Actual contribution-frame erasure consumers of the existing image verifier."""
import json
import re

from cff_build import run


def frame_refusals(args, directory, protected, report, binary, checker, build_image):
    claimed = json.loads(report.read_text())
    original = protected.read_text()
    count = 0
    for component, target in (("call-frames", "contribution_preparation_defined"),
            ("external-calls", "contribution_preparation_imported")):
        helper = next(row["function"] for row in claimed["functions"]
            if row.get("generation_component") == component and row.get("generated_owner") == "contribution_compute")
        body = re.search(rf"(?ms)^define internal void @{re.escape(helper)}\(.*?^}}", original)
        if body is None: raise AssertionError("actual frame helper body is missing")
        changed, replaced = re.subn(r"(call i32 )%[\w.]+(\(i32 )", rf"\g<1>@{target}\2", body[0])
        if replaced != 1: raise AssertionError("frame erasure did not reach the typed target call")
        source = directory / (component + "-erased.ll")
        source.write_text(original[:body.start()] + changed + original[body.end():])
        run([args.opt, "-passes=verify", "-disable-output", source])
        image = build_image(component + "-erased", source)
        if "gate-normal-completed" not in run([image]).stdout:
            raise AssertionError("directifying a frame target changed reference semantics")
        final = directory / (component + "-erased.final.json")
        result = run([*checker, image, report, "--output", final], succeeds=False)
        if "lost typed frame invoker" not in result.stderr or final.exists():
            raise AssertionError(f"frame erasure failed outside its final invoker gate: {result.stderr}")
        count += 1

        # Keep the genuine helper in the image. A forwarding call cannot borrow its
        # presence when the owning caller no longer dispatches to it directly.
        wrapper = helper + ".forwarded"
        owner = re.search(r"(?ms)^define [^\n]*@contribution_compute\(.*?^}", original)
        changed, replaced = re.subn(rf"@{re.escape(helper)}\(ptr ", f"@{wrapper}(ptr ", owner[0])
        if replaced != 1: raise AssertionError("caller route replacement escaped its one real call")
        redirected = original[:owner.start()] + changed + original[owner.end():]
        source = directory / (component + "-forwarded.ll")
        source.write_text(redirected + f"\ndefine internal void @{wrapper}(ptr %frame) noinline {{\n"
            f"  call void @{helper}(ptr %frame)\n  ret void\n}}\n")
        run([args.opt, "-passes=verify", "-disable-output", source])
        image = build_image(component + "-forwarded", source)
        if "gate-normal-completed" not in run([image]).stdout:
            raise AssertionError("forwarding a frame changed reference semantics")
        final = directory / (component + "-forwarded.final.json")
        result = run([*checker, image, report, "--output", final], succeeds=False)
        if "lost an owned call frame route" not in result.stderr or final.exists():
            raise AssertionError(f"forwarding helper borrowed the original route evidence: {result.stderr}")
        count += 1

        missing = json.loads(json.dumps(claimed))
        missing["functions"] = [row for row in missing["functions"] if row["function"] != helper]
        bad = directory / (component + "-missing-helper.json")
        bad.write_text(json.dumps(missing))
        result = run([*checker, binary, bad], succeeds=False)
        if "call frame helper inventory is incomplete" not in result.stderr:
            raise AssertionError("missing helper inventory received final frame credit")
        count += 1
    return count
