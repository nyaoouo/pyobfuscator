"""Validation/alias preservation and explicit pre-release selection constraints."""
import json
from pathlib import Path
import sys

from finalize_measured_release import finalize, verify
from reference_plan import parse_plan


def completion_cases(args, directory, raw, final, plan, material, draft, run, rejects):
    root = Path(__file__).resolve().parents[1]
    inputs = [directory / name for name in ("cli.raw.dll", "cli.plan.json", "cli.material.json", "cli.draft")]
    values = (raw, args.plan.read_bytes(), args.material.read_bytes(), draft)
    for path, value in zip(inputs, values): path.write_bytes(value)
    output, report = directory / "cli.final.dll", directory / "cli.final.json"
    output.write_bytes(b"preserve image"); report.write_bytes(b"preserve report")
    cli = [sys.executable, root / "tools/finalize_measured_release.py", *inputs, output, "--report", report]
    for index, bad in ((1, b"{}"), (2, b"{}"), (3, bytes(64))):
        inputs[index].write_bytes(bad); run(cli, succeeds=False); inputs[index].write_bytes(values[index])
        if (output.read_bytes(), report.read_bytes()) != (b"preserve image", b"preserve report"):
            raise AssertionError("validation failure replaced prior measured outputs")
    for path in inputs:
        run([*cli[:-3], path, "--report", report], succeeds=False)
        run([*cli[:-1], path], succeeds=False)
    run([*cli[:-1], output], succeeds=False)
    if tuple(path.read_bytes() for path in inputs) != values:
        raise AssertionError("measured output alias replaced an input")
    run(cli)
    completed, proof = output.read_bytes(), json.loads(report.read_text())
    if verify(raw, completed, plan, material, draft) != proof:
        raise AssertionError("CLI measured output/proof differs from independent recomputation")
    inputs[0].write_bytes(final)
    damaged = bytearray(draft); damaged[24] ^= 1; inputs[3].write_bytes(damaged)
    run(cli, succeeds=False)
    if output.read_bytes() != completed or json.loads(report.read_text()) != proof:
        raise AssertionError("stale finalized mask rewrote prior outputs")
    inputs[3].write_bytes(draft)
    in_place = [sys.executable, root / "tools/finalize_measured_release.py", *inputs, inputs[0], "--report", report]
    run(in_place, succeeds=False)
    if inputs[0].read_bytes() != final: raise AssertionError("rejected in-place completion rewrote input")
    for change in ("post-stage", "external", "multiple"):
        document = json.loads(plan.canonical)
        if change == "post-stage": document["records"][0]["stage"] = 2
        elif change == "external": document["records"][0]["image"] = bytes(range(1, 17)).hex()
        else:
            document["records"].append(dict(document["records"][0])); document["records"][1]["owner"] = 2
        invalid = parse_plan(json.dumps(document).encode())
        rejects(lambda invalid=invalid: finalize(raw, invalid, material, draft))
