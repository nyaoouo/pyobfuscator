"""Use the existing independent word reference for finalized scoped-slot consumers."""
from pathlib import Path
import struct
import sys

from check_capture import ROOT
from reference_plan import parse_plan
from release_material import material_fold, parse_material

sys.path.insert(0, str(ROOT / "tests/contribution"))
from check_context import context_word


def write_inputs(path, plan_path, material_path, materials):
    plan = parse_plan(Path(plan_path).read_bytes())
    words = material_fold(parse_material(Path(material_path).read_bytes()))
    expected = [context_word(struct.unpack("<8I", Path(materials[index]).read_bytes()), 0x1020,
        (1, record.identity.owner, 11, 13, 0)) if index in materials else 0
        for index, record in enumerate(plan.records)]
    Path(path).write_bytes(struct.pack("<8I", *words) + struct.pack(f"<{len(expected)}I", *expected))
