"""Check actual demo lifecycle transcripts against the independent build reference."""

from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import path_fold_reference as fold
from release_plan import parse_plan
from pe_release_record import finalize_image


def verify_transcript(text, plan):
    events = plan["events"]
    initial = fold.initialize(plan["seed"])
    def advance(state, role):
        return fold.advance(state, events[role]["tag"], events[role]["word"])
    environment = advance(initial, "environment")
    support = advance(environment, "support")
    expected = {
        "initialize": initial, "environment": environment, "support": support,
        "release": advance(support, "release"),
        "skip-environment": advance(advance(initial, "support"), "release"),
        "skip-support": advance(environment, "release"),
    }
    observed = {}
    for line in text.splitlines():
        if not line.startswith("bootstrap-fold "): continue
        _, name, *words = line.split()
        if name in observed: raise AssertionError("duplicate actual bootstrap fold checkpoint")
        observed[name] = tuple(map(int, words))
    if observed != expected: raise AssertionError("actual bootstrap transcript differs from independent build reference")
    if expected["release"] in (expected["skip-environment"], expected["skip-support"]):
        raise AssertionError("omitted lifecycle data did not perturb the release fold")


def diagnostic_output(text):
    return "\n".join(line for line in text.splitlines() if not line.startswith("bootstrap-fold "))


def verify_coverage(rows, *, decoy=False):
    bound = [row for row in rows if row.get("path_fold", {}).get("ir_binding_contract_verified")]
    expected = {"initialize_session": "initialize32x8", "pass_environment_gate": "advance32x8",
                "dispatch_lifecycle": "advance32x8", "release_and_load_payload": "advance32x8"}
    if decoy:
        expected.update({"initialize_decoy": "initialize32x8", "advance_decoy_selection": "advance32x8",
                         "advance_decoy_preparation": "advance32x8", "release_decoy": "advance32x8"})
    if len(bound) != len(expected): raise AssertionError("actual bootstrap fold function scope changed")
    for name, kind in expected.items():
        matches = [row for row in bound if name in row["function"]]
        if len(matches) != 1: raise AssertionError("critical bootstrap fold function is absent or duplicated")
        row = matches[0]
        component = next(item for item in row["components"] if item["component"] == "path-fold")
        if (row["status"] != "transformed" or component["requested"] != 1 or component["applied"] != 1 or
                component["unsupported"] or component["applied_roles"] != {"real": 1} or
                component["applied_types"] != {kind: 1}):
            raise AssertionError("required bootstrap fold was not credited to its original real site")


if __name__ == "__main__":
    source, plan_path, record_path = map(Path, sys.argv[1:])
    plan = parse_plan(plan_path.read_bytes())
    with tempfile.TemporaryDirectory(dir=source.parent) as temporary:
        binary = Path(temporary) / "session.exe"
        binary.write_bytes(finalize_image(source.read_bytes(), record_path.read_bytes())[0])
        result = subprocess.run([binary], capture_output=True, text=True, timeout=30)
        if result.returncode: raise AssertionError(diagnostic_output(result.stdout) + result.stderr)
        verify_transcript(result.stdout, plan)
        print(diagnostic_output(result.stdout))
        print("six private bootstrap checkpoints matched the independent build input")
