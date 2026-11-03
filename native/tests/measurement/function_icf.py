"""Prove actual LLVM linker folding, with an unchanged-object unfolded counterpart."""
import ctypes
import os
from pathlib import Path

from cff_build import run
from coff_symbols import image_symbols
from function_subject import function_subject
from pe_layout import parse_image

ROOT = Path(__file__).resolve().parents[2]


def check_icf(compiler, directory):
    obj = directory / "icf.obj"
    run([compiler, "-c", ROOT / "tests/measurement/function_icf.s", "-o", obj])
    original = obj.read_bytes()
    for mode in ("none", "all"):
        dll = directory / f"icf-{mode}.dll"
        run([compiler, "-fuse-ld=lld", "-shared", obj, f"-Wl,--icf={mode}", "-o", dll])
        data = dll.read_bytes(); image = parse_image(data)
        values = {symbol.name: image.layout.sections[symbol.section - 1].rva + symbol.value
            for symbol in image_symbols(data, image) if symbol.name in ("twin_a", "twin_b") and symbol.section > 0}
        if len(values) != 2 or (values["twin_a"] == values["twin_b"]) != (mode == "all"):
            raise AssertionError("actual ICF on/off fixture did not change function address identity")
        with os.add_dll_directory(str(compiler.parent.resolve())):
            library = ctypes.WinDLL(str(dll.resolve()))
            try:
                a = ctypes.cast(library.twin_a, ctypes.c_void_p).value
                b = ctypes.cast(library.twin_b, ctypes.c_void_p).value
                if a - library._handle != values["twin_a"] or b - library._handle != values["twin_b"]:
                    raise AssertionError("live exported function addresses disagree with final symbol mapping")
            finally:
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.FreeLibrary.argtypes = [ctypes.c_void_p]; kernel.FreeLibrary.restype = ctypes.c_int
                if not kernel.FreeLibrary(library._handle): raise OSError(ctypes.get_last_error(), "close ICF fixture")
        for name in values:
            try: function_subject(original, data, image, 901, name)
            except ValueError as error:
                if mode != "all" or "folded, aliased" not in str(error): raise
            else:
                if mode == "all": raise AssertionError("genuinely folded function accepted as independent")
    print("same real object: LLVM ICF-off accepts both extents; actual ICF-all shared-address functions refuse")
