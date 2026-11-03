"""Real data-section fixups and retained-label mapping failures for closed functions."""
import ctypes
import struct

from coff_layout import parse_object
from coff_symbols import image_symbols
from function_subject import function_subject
from pe_layout import parse_image


def check_data_targets(args, directory, run, check_native):
    from check_capture import ROOT
    for optimization in ("O0", "O2"):
        obj, dll = (directory / ("data-" + optimization + suffix) for suffix in (".obj", ".dll"))
        run([args.compiler, "-" + optimization, "-fno-lto", "-ffunction-sections", "-c",
            ROOT / "tests/measurement/function_data_fixture.cpp", "-o", obj])
        source = obj.read_bytes(); parsed = parse_object(source)
        root = next(symbol for symbol in parsed.symbols if symbol.name == "extent_data_target")
        section = parsed.sections[root.section - 1]
        symbols = {symbol.index: symbol for symbol in parsed.symbols}
        table = struct.unpack_from("<I", source, 20 + 40 * (section.index - 1) + 24)[0]
        changed = bytearray(source); selected = set()
        for index, relocation in enumerate(section.relocations):
            target = symbols[relocation.target]
            if target.name not in ("extent_data_bss", "extent_data_rw", "extent_data_ro"): continue
            if relocation.kind != 4: raise AssertionError("data fixture lost its actual RIP-relative fields")
            target_section = parsed.sections[target.section - 1]
            definition = next(symbol for symbol in parsed.symbols if symbol.section == target.section and
                symbol.name == target_section.name and symbol.auxiliaries)
            offset = section.offset + relocation.offset
            addend = struct.unpack_from("<i", source, offset)[0]
            struct.pack_into("<i", changed, offset, addend + target.value)
            struct.pack_into("<I", changed, table + index * 10 + 4, definition.index)
            selected.add(target.section)
        if len(selected) != 3: raise AssertionError("data fixture needs actual BSS/writable/readonly targets")
        obj.write_bytes(changed)
        run([args.compiler, "-shared", "-fno-lto", obj, "-o", dll])
        data = dll.read_bytes(); image = parse_image(data)
        linked = image_symbols(data, image)
        pe = struct.unpack_from("<I", data, 60)[0]
        final_table = struct.unpack_from("<I", data, pe + 12)[0]
        section_names = {parsed.sections[index - 1].name for index in selected}
        # Generic output section names are not a contribution map. Keep all actual data
        # labels while removing that accidental shortcut from the debug symbol table.
        hidden = bytearray(data)
        for symbol in linked:
            if symbol.name in section_names:
                hidden[final_table + symbol.index * 18:final_table + symbol.index * 18 + 8] = b"omitsect"
        data = bytes(hidden); dll.write_bytes(data); image = parse_image(data)
        subject = function_subject(bytes(changed), data, image, 0x510, root.name)
        check_native(args.probe, args.runtime_directory, directory, dll, data, image, subject)
        library = ctypes.WinDLL(str(dll.resolve()))
        try:
            function = library.extent_data_target
            function.argtypes = [ctypes.c_uint]; function.restype = ctypes.c_uint
            for value in (0, 1, 3, 31, 0xffffffff):
                expected = (value + 19 + (3, 5, 11, 23)[value & 3]) & 0xffffffff
                if function(value) != expected: raise AssertionError("actual section-target fixups changed execution")
        finally:
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.FreeLibrary.argtypes = [ctypes.c_void_p]; kernel.FreeLibrary.restype = ctypes.c_int
            if not kernel.FreeLibrary(library._handle): raise OSError(ctypes.get_last_error(), "close data fixture")

        bss = next(section for section in parsed.sections if section.index in selected and section.flags & 0x80)
        anchors = [symbol for symbol in parsed.symbols if symbol.section == bss.index and not symbol.auxiliaries]
        final_symbols = {symbol.name: symbol for symbol in image_symbols(data, image)}
        if len(anchors) != 2: raise AssertionError("data fixture needs two independent BSS labels")
        prefix = next(symbol for symbol in anchors if symbol.value == 0)
        body = next(symbol for symbol in anchors if symbol.value != 0)
        def rename(output, anchor):
            position = final_table + final_symbols[anchor.name].index * 18
            output[position:position + 8] = b"omitdata"
        nonzero = bytearray(data); rename(nonzero, prefix)
        function_subject(bytes(changed), bytes(nonzero), parse_image(bytes(nonzero)), 0x511, root.name)

        def refuses(output):
            try: function_subject(bytes(changed), bytes(output), parse_image(bytes(output)), 0x512, root.name)
            except ValueError as error:
                if "lacks an exact final target" not in str(error): raise
            else: raise AssertionError("unproven data contribution mapping was accepted")
        conflict = bytearray(data)
        position = final_table + final_symbols[body.name].index * 18 + 8
        struct.pack_into("<I", conflict, position, final_symbols[body.name].value + 1)
        refuses(conflict)
        missing = bytearray(data)
        for anchor in anchors: rename(missing, anchor)
        refuses(missing)
        outside = bytearray(data)
        final_section = image.layout.sections[final_symbols[body.name].section - 1]
        base = (final_section.virtual_size or final_section.raw_size) - 1
        for anchor in anchors:
            position = final_table + final_symbols[anchor.name].index * 18 + 8
            struct.pack_into("<I", outside, position, base + anchor.value)
        refuses(outside)
    print("actual O0/O2 BSS/writable/readonly contribution targets and nonzero labels pass; conflict/missing/overflow mappings refuse")
