"""Prove closed compiler-owned contributions against their actual final PE ranges."""
from code_subject import MAX_BYTES, MAX_RANGES, Range, Subject, validate_subject
from coff_layout import parse_object
from coff_relocations import Resolver, linked_bytes
from coff_symbols import image_symbols
from pe_layout import read_rva


def function_subject(object_data, data, image, tag, name, *, aliases=(), fragments=()):
    if (type(name) is not str or not name or len(name) > 256 or
            type(aliases) is not tuple or type(fragments) is not tuple or
            any(type(item) is not str or not item or len(item) > 4096 for item in (*aliases, *fragments)) or
            len(set((name, *aliases, *fragments))) != 1 + len(aliases) + len(fragments)):
        raise ValueError("COFF function needs an exact root and distinct declared aliases/fragments")
    obj = parse_object(object_data)
    roots = [symbol for symbol in obj.symbols if symbol.name == name and symbol.type == 0x20 and symbol.section > 0]
    if len(roots) != 1 or roots[0].value != 0:
        raise ValueError("COFF function needs one offset-zero root definition")
    root = obj.sections[roots[0].section - 1]
    if root.parent: raise ValueError("COFF function root is itself an owned fragment")
    root_names = {symbol.name for symbol in obj.symbols if symbol.section == root.index and symbol.type == 0x20}
    if root_names != {name, *aliases} or any(symbol.value for symbol in obj.symbols
            if symbol.section == root.index and symbol.type == 0x20):
        raise ValueError("COFF function has undeclared aliases or mixed function ownership")
    linked = image_symbols(data, image)
    resolver = Resolver(obj, image, linked)
    included = [section for section in obj.sections if
        obj.owners[section.index - 1] == root.index and section.flags & 0x20000000]
    if any(symbol.type == 0x20 and symbol.section > 0 and obj.owners[symbol.section - 1] == root.index and
            not obj.sections[symbol.section - 1].flags & 0x20000000 for symbol in obj.symbols):
        raise ValueError("COFF owned function anchor is not executable")
    if not included: raise ValueError("COFF function has no executable ownership closure")
    if len(included) > MAX_RANGES or sum(section.size for section in included) > MAX_BYTES:
        raise ValueError("COFF function exceeds the subject range/byte budget")
    actual_fragments = {symbol.name for symbol in obj.symbols if symbol.type == 0x20 and symbol.section > 0 and
        symbol.section != root.index and obj.owners[symbol.section - 1] == root.index and
        obj.sections[symbol.section - 1].flags & 0x20000000}
    if actual_fragments != set(fragments):
        raise ValueError("COFF function ownership disagrees with required executable fragments")
    ranges = []
    for section in included:
        if not section.size or section.flags & 0x60000020 != 0x60000020 or section.flags & 0x82000000:
            raise ValueError("COFF function contribution needs stable readable executable code")
        functions = [symbol for symbol in obj.symbols if symbol.section == section.index and symbol.type == 0x20]
        if not functions or any(symbol.value for symbol in functions):
            raise ValueError("COFF owned code fragment lacks exact offset-zero function anchors")
        addresses = {resolver.named(symbol.name) for symbol in functions}
        if len(addresses) != 1: raise ValueError("COFF final aliases do not share their declared body")
        start = addresses.pop()
        expected_names = {symbol.name for symbol in functions}
        found = {symbol.name for symbol in linked if symbol.type == 0x20 and symbol.section > 0 and
            start <= image.layout.sections[symbol.section - 1].rva + symbol.value < start + section.size}
        if found != expected_names:
            raise ValueError("COFF final function extent is folded, aliased or contains another function")
        if linked_bytes(object_data, obj, section, start, resolver) != read_rva(data, image, start, section.size):
            raise ValueError("COFF final contribution bytes disagree after exact relocation evaluation")
        ranges.append(Range(start, section.size))
    return validate_subject(image, Subject(tag, "function-contribution", name,
        tuple(sorted(ranges, key=lambda span: span.rva))))
