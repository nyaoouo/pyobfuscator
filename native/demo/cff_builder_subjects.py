"""Bind four mixed POST compiler functions to their exact linked PE extents."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from cff_joint_machine_evidence import MEASURED, OWNED
from function_subject import function_subject
from payload_binding import OWNER, WRAPPER
from pe_layout import parse_image


SUBJECTS = (OWNER, WRAPPER, OWNED, MEASURED)


def verify_builder_subjects(object_bytes: bytes, image_bytes: bytes) -> dict:
    """Require exact COFF relocation and extent mapping for the four symbols."""
    if (type(object_bytes) is not bytes or not object_bytes or
            type(image_bytes) is not bytes or not image_bytes):
        raise ValueError("builder subjects need actual object and PE bytes")
    image = parse_image(image_bytes)
    subjects = []
    all_ranges = []
    for index, name in enumerate(SUBJECTS):
        try:
            subject = function_subject(object_bytes, image_bytes, image,
                                       0xb300 + index, name)
        except ValueError as error:
            raise ValueError(f"builder subject {name}: {error}") from error
        if subject.kind != "function-contribution" or subject.label != name or not subject.ranges:
            raise ValueError(f"builder subject {name}: incomplete function extent")
        ranges = []
        for span in subject.ranges:
            if span.size <= 0:
                raise ValueError(f"builder subject {name}: empty function extent")
            ranges.append({"rva": span.rva, "size": span.size})
            all_ranges.append((span.rva, span.rva + span.size, name))
        subjects.append({"symbol": name, "ranges": ranges})
    all_ranges.sort()
    for previous, current in zip(all_ranges, all_ranges[1:]):
        if previous[1] > current[0]:
            raise ValueError(f"builder subjects overlap: {previous[2]} and {current[2]}")
    return {"verified": True, "scope": "exact-coff-relocated-pe-functions-v1",
            "subjects": subjects}
