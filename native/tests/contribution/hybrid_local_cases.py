"""Independent hybrid stack inventory and executable local-route ablation."""
import json
import re
import subprocess

from cff_build import run
from edge_policies import function_body
from preparation_cases import alternate


def check_hybrid_locals(rows, source, protected):
    original = function_body(source.read_text(), "contribution_hybrid")
    actual = function_body(protected.read_text(), "contribution_hybrid")
    allocations = dict(re.findall(r"(?m)^  (%[\w.$-]+) = alloca ([^\n]+)", original))
    for line in original.splitlines():
        if "!pyobf.archive.gate" not in line:
            continue
        frame = re.search(r"\(ptr (%[\w.$-]+),", line)[1]
        if not allocations.get(frame, "").startswith("[8 x i32],"):
            raise AssertionError("actual archive acquisition lost its independent compiler key frame")
        del allocations[frame]
    objects = len(allocations)
    row = next(row for row in rows if row["function"] == "contribution_hybrid")
    component = next(item for item in row["components"] if item["component"] == "indexed-locals")
    metrics = component["preparation"]
    slots = 2
    while slots <= objects:
        slots *= 2
    if (not objects or component["applied"] != objects or component["unsupported"] or
            metrics["objects"] != objects or metrics["table_slots"] != slots or
            metrics["per_invocation_bytes"] != 8 * slots or metrics["address_routes"] < objects or
            sum(component["applied_types"].values()) != objects):
        raise AssertionError("hybrid local coverage differs from retained original stack objects")
    lifetimes = r"@llvm\.lifetime\.(?:start|end)\.p0\("
    if len(re.findall(lifetimes, original)) != len(re.findall(lifetimes, actual)):
        raise AssertionError("hybrid local routing changed original lifetime marker inventory")
    if "!pyobf.local." in actual:
        raise AssertionError("hybrid local private construction data leaked")
    print(f"{objects} retained hybrid objects/{metrics['address_routes']} state-bound address routes verified")


def hybrid_local_refusals(args, directory, transform, private, configuration,
                          protected, claimed, checker, build_image):
    config = json.loads(configuration.read_text())
    config["functions"]["contribution_hybrid"]["components"]["indexed-locals"] = "off"
    source, _ = alternate(args, directory, transform, private, config, "hybrid-locals-erased")
    image = build_image("hybrid-locals-erased", source)
    if "gate-normal-completed" not in run([image]).stdout:
        raise AssertionError("hybrid local ablation changed reference EH/cleanup semantics")
    final = directory / "hybrid-locals-erased.final.json"
    result = run([*checker, image, claimed, "--output", final], succeeds=False)
    if "lost indexed local address routes: contribution_hybrid" not in result.stderr or final.exists():
        raise AssertionError("hybrid local ablation borrowed another owner's routes: " + result.stderr)

    original = protected.read_text()
    body = function_body(original, "contribution_hybrid")
    changed, count = re.subn(r"(%pyobf\.local\.state\d*) = (load i32, ptr %pyobf\.state(?:, align \d+)?)",
        lambda match: f"{match[1]}.wrong = {match[2]}\n  {match[1]} = xor i32 {match[1]}.wrong, 1", body)
    if not count:
        raise AssertionError("hybrid local wrong-state mutation missed its actual source reads")
    source = directory / "hybrid-locals-wrong-state.ll"
    source.write_text(original.replace(body, changed, 1))
    run([args.opt, "-passes=verify", "-disable-output", source])
    image = build_image("hybrid-locals-wrong-state", source)
    try:
        result = subprocess.run([image], capture_output=True, text=True, timeout=3)
        if result.returncode == 0 and "gate-normal-completed" in result.stdout:
            raise AssertionError("wrong local state retained actual hybrid execution")
        if "gate-enter" not in result.stdout:
            raise AssertionError("wrong local state failed before entering the actual fixture")
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b""
        if isinstance(output, bytes): output = output.decode(errors="replace")
        if "gate-enter" not in output:
            raise AssertionError("wrong local state timeout occurred before fixture entry") from None
    print("hybrid local normal-preserving erasure and live wrong-state execution refused")
