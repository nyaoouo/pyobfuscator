"""Actual-object/final-image mutations against production function ownership and fixups."""
import struct

from coff_layout import parse_object
from coff_symbols import image_symbols
from function_subject import function_subject
from pe_layout import parse_image


def changed(data, offset, fmt, value):
    result = bytearray(data); struct.pack_into(fmt, result, offset, value); return bytes(result)


def check_cases(original, fragments, final):
    obj = parse_object(original); split = parse_object(fragments); image = parse_image(final)
    table = struct.unpack_from("<I", original, 8)[0]
    split_table = struct.unpack_from("<I", fragments, 8)[0]
    pe = struct.unpack_from("<I", final, 60)[0]
    final_table = struct.unpack_from("<I", final, pe + 12)[0]
    strings = table + struct.unpack_from("<I", original, 12)[0] * 18
    leaf = next(symbol for symbol in obj.symbols if symbol.name == "extent_leaf")
    eh = next(symbol for symbol in obj.symbols if symbol.name == "extent_eh")
    section = obj.sections[eh.section - 1]
    section_header = 20 + 40 * (section.index - 1)
    relocations = struct.unpack_from("<I", original, section_header + 24)[0]
    definition = next(symbol for symbol in obj.symbols if symbol.name == section.name and symbol.section == section.index)
    cold = next(symbol for symbol in split.symbols if symbol.name == "extent_cold")
    cold_section = split.sections[cold.section - 1]
    cold_definition = next(symbol for symbol in split.symbols if symbol.name == cold_section.name and symbol.section == cold.section)
    cold_aux = split_table + 18 * (cold_definition.index + 1)
    syms = image_symbols(final, image)
    linked_leaf = next(symbol for symbol in syms if symbol.name == "extent_leaf")
    linked_eh = next(symbol for symbol in syms if symbol.name == "extent_eh")
    linked_throw = next(symbol for symbol in syms if symbol.name == "extent_throw")
    linked_alias = next(symbol for symbol in syms if symbol.name == "extent_alias")
    final_eh_section = image.layout.sections[linked_eh.section - 1]
    leaf_offset = image.layout.sections[linked_leaf.section - 1].raw_offset + linked_leaf.value
    eh_offset = final_eh_section.raw_offset + linked_eh.value
    passed = []

    def refuses(label, callback, message):
        try: callback()
        except ValueError as error:
            if message not in str(error): raise AssertionError(f"{label}: wrong refusal source: {error}") from error
            passed.append(label)
        else: raise AssertionError(f"{label}: invalid contribution/image was accepted")

    def ordinary(source=original, output=final, name="extent_eh"):
        return function_subject(source, output, parse_image(output), 1001, name)

    def fragmented(source=fragments, output=final, **options):
        return function_subject(source, output, parse_image(output), 1002, "extent_split",
            aliases=options.get("aliases", ("extent_alias",)), fragments=options.get("fragments", ("extent_cold",)))

    refuses("short header", lambda: parse_object(original[:19]), "header")
    refuses("wrong architecture", lambda: parse_object(changed(original, 0, "<H", 0x14c)), "AMD64")
    refuses("missing sections", lambda: parse_object(changed(original, 2, "<H", 0)), "AMD64")
    refuses("image instead of object", lambda: parse_object(changed(original, 16, "<H", 240)), "relocatable")
    refuses("symbol budget", lambda: parse_object(changed(original, 12, "<I", (1 << 20) + 1)), "bounded symbol")
    refuses("bad string size", lambda: parse_object(changed(original, strings, "<I", 3)), "string table")
    refuses("raw span outside file", lambda: parse_object(changed(original, section_header + 20, "<I", len(original))), "section bytes")
    refuses("raw span overlaps header", lambda: parse_object(changed(original, section_header + 20, "<I", 20)), "overlap")
    refuses("auxiliary length mismatch", lambda: parse_object(changed(original, table + 18 * (definition.index + 1), "<I", section.size - 1)), "disagrees")
    refuses("auxiliary relocation target", lambda: parse_object(changed(original, relocations + 4, "<I", definition.index + 1)), "auxiliary symbol")
    refuses("symbol beyond contribution", lambda: parse_object(changed(original, table + 18 * leaf.index + 8, "<I", len(original))), "outside its input")
    refuses("unknown link fixup", lambda: ordinary(changed(original, relocations + 8, "<H", 0)), "relocation kind")
    refuses("link fixup straddles", lambda: ordinary(changed(original, relocations, "<I", section.size - 2)), "crosses")
    refuses("overlapping link fixups", lambda: ordinary(changed(original, relocations + 10, "<I", section.relocations[0].offset)), "overlap")
    refuses("changed leaf instruction", lambda: ordinary(output=changed(final, leaf_offset, "<B", final[leaf_offset] ^ 1), name="extent_leaf"), "bytes disagree")
    fixup_offset = eh_offset + section.relocations[0].offset
    refuses("changed linked fixup", lambda: ordinary(output=changed(final, fixup_offset, "<B", final[fixup_offset] ^ 1)), "bytes disagree")
    refuses("changed link target identity", lambda: ordinary(output=changed(final, final_table + linked_throw.index * 18 + 8,
        "<I", linked_throw.value + 1)), "bytes disagree")
    stripped = changed(changed(final, pe + 12, "<I", 0), pe + 16, "<I", 0)
    refuses("stripped final symbols", lambda: ordinary(output=stripped), "bounded symbol")
    alias_output = changed(changed(final, final_table + linked_throw.index * 18 + 8, "<I", linked_leaf.value),
        final_table + linked_throw.index * 18 + 12, "<h", linked_leaf.section)
    refuses("final undeclared folding", lambda: ordinary(output=alias_output, name="extent_leaf"), "folded, aliased")
    refuses("missing alias declaration", lambda: fragmented(aliases=()), "undeclared aliases")
    refuses("invented alias declaration", lambda: fragmented(aliases=("missing_alias",)), "undeclared aliases")
    shifted = changed(final, final_table + linked_alias.index * 18 + 8, "<I", linked_alias.value + 1)
    refuses("detached final alias", lambda: fragmented(output=shifted), "aliases do not share")
    refuses("missing required fragment", lambda: fragmented(fragments=("missing_fragment",)), "required executable fragments")
    refuses("unaccounted fragment", lambda: fragmented(fragments=()), "required executable fragments")
    refuses("association self cycle", lambda: fragmented(changed(fragments, cold_aux + 12, "<h", cold.section)), "cyclic")
    refuses("invalid association parent", lambda: fragmented(changed(fragments, cold_aux + 12, "<h", len(split.sections) + 1)), "metadata disagrees")
    refuses("unmodelled high association number", lambda: fragmented(changed(fragments, cold_aux + 16, "<H", 1)), "metadata disagrees")
    refuses("removed association", lambda: fragmented(changed(fragments, cold_aux + 14, "<B", 1)), "required executable fragments")
    cold_flags = 20 + 40 * (cold.section - 1) + 36
    refuses("hidden non-executable function fragment", lambda: fragmented(changed(fragments, cold_flags, "<I",
        cold_section.flags & ~0x20000000), fragments=()), "anchor is not executable")
    refuses("fragment interior anchor", lambda: fragmented(changed(fragments, split_table + 18 * cold.index + 8, "<I", 1)), "offset-zero")
    root_flags = 20 + 40 * (leaf.section - 1) + 36
    refuses("writable input code", lambda: ordinary(changed(original, root_flags, "<I",
        obj.sections[leaf.section - 1].flags | 0x80000000), name="extent_leaf"), "stable readable executable")
    string_size = struct.unpack_from("<I", original, strings)[0]
    dangling = changed(changed(original, table + 18 * leaf.index, "<Q", (string_size - 1) << 32),
        strings + string_size - 1, "<B", 65)
    refuses("unterminated symbol name", lambda: parse_object(dangling), "unterminated")
    print(f"{len(passed)} actual object/image function ownership/fixup refusals pass")
