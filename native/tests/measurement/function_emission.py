"""Use the production CMake emitter, preserving default codegen and closed ownership."""
import hashlib
from pathlib import Path

from check_capture import ROOT
from cff_build import run


def emit_functions(args, directory, native, transformed):
    original = native.read_bytes()
    source, build = directory / "emission-source", directory / "emission-build"
    source.mkdir()
    default, direct = directory / "default.obj", directory / "direct-function.obj"
    def quote(path): return '"' + Path(path).resolve().as_posix() + '"'
    helper = quote(ROOT / "cmake/LLVMCompile.cmake")
    body = ('cmake_minimum_required(VERSION 3.24)\nproject(function_emission LANGUAGES CXX)\n'
        f'include({helper})\n'
        f'pyobf_native_emit_object({quote(default)} {quote(transformed)})\n'
        f'pyobf_native_emit_object({quote(native)} {quote(transformed)} FUNCTION_SECTIONS)\n'
        f'add_custom_target(emission ALL DEPENDS {quote(default)} {quote(native)})\n')
    (source / "CMakeLists.txt").write_text(body)
    configure = [args.cmake, "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={args.ninja}",
        f"-DCMAKE_CXX_COMPILER={args.compiler}", f"-DCMAKE_INTERPROCEDURAL_OPTIMIZATION={'ON' if args.ipo else 'OFF'}"]
    run([*configure, "-S", source, "-B", build])
    command = [args.cmake, "--build", build, "--target", "emission", "-j", "2"]
    run(command)
    run([args.compiler, "-O0", "-fno-lto", "-ffunction-sections", "-c", transformed, "-o", direct])
    if default.read_bytes() != original or native.read_bytes() != direct.read_bytes():
        raise AssertionError("production default/function emitter changed the established codegen contract")
    snapshot = {path: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).digest()) for path in (default, native)}
    unchanged = run(command)
    if "no work to do" not in unchanged.stdout or any(
            (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).digest()) != value for path, value in snapshot.items()):
        raise AssertionError("unchanged function emission rebuilt its objects")
    invalid = directory / "invalid-emission"; invalid.mkdir()
    (invalid / "CMakeLists.txt").write_text('cmake_minimum_required(VERSION 3.24)\n'
        'project(invalid_emission LANGUAGES CXX)\n' + f'include({helper})\n'
        f'pyobf_native_emit_object({quote(directory / "invalid.obj")} {quote(transformed)} FUNCTION_SECTONS)\n')
    failure = run([*configure, "-S", invalid, "-B", directory / "invalid-build"], succeeds=False)
    if "unknown emission arguments" not in failure.stderr or (directory / "invalid.obj").exists():
        raise AssertionError("unsupported function emission did not fail at configuration")
    print("production function-section/default exact objects, parent-IPO isolation, typo refusal and no-change pass")
    return default
