"""Actual linked fields independently exercise all admitted AMD64 object fixups."""
from pathlib import Path
import struct

from cff_build import run
from coff_layout import parse_object
from function_subject import function_subject
from pe_layout import parse_image
from code_observation import reference_digest

ROOT = Path(__file__).resolve().parents[2]


def check_relocations(compiler, directory):
    obj, dll = directory / "relocations.obj", directory / "relocations.dll"
    run([compiler, "-c", ROOT / "tests/measurement/function_relocations.s", "-o", obj])
    original = obj.read_bytes(); parsed = parse_object(original)
    section = next(section for section in parsed.sections if section.name == ".text$extent_reloc")
    # LLVM's .reloc parser does not expose the COFF REL32_n names. Make valid COFF input
    # fields before linking; the actual linker, not the evaluator, supplies expected bytes.
    header = 20 + 40 * (section.index - 1)
    table = struct.unpack_from("<I", original, header + 24)[0]
    positions = [index for index, relocation in enumerate(section.relocations) if relocation.kind == 4]
    if len(positions) != 6: raise AssertionError("authored REL32 field inventory differs")
    changed = bytearray(original)
    for adjustment, position in enumerate(positions):
        struct.pack_into("<H", changed, table + position * 10 + 8, 4 + adjustment)
    kinds = {relocation.kind for section in parse_object(bytes(changed)).sections for relocation in section.relocations}
    if kinds != set(range(1, 10)): raise AssertionError("actual input lost an admitted AMD64 relocation kind")
    obj.write_bytes(changed)
    run([compiler, "-shared", obj, "-Wl,--image-base,0x10000000", "-o", dll])
    data = dll.read_bytes(); image = parse_image(data)
    subject = function_subject(bytes(changed), data, image, 912, "extent_reloc")
    try: reference_digest(data, image, subject, 7)
    except ValueError as error:
        if "admits DIR64 only" not in str(error): raise
    else: raise AssertionError("DIR64-only canonicalizer silently admitted ADDR32/HIGHLOW code")
    print("actual link evaluates ADDR64/ADDR32/ADDR32NB/REL32_0..5; native DIR64-only scope refuses HIGHLOW")
