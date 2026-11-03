"""Exercise the private CMake storage/finalization dependency chains."""
import hashlib
import json
from pathlib import Path
import struct

from check_capture import ROOT
from release_material import material_fold


def check_pipeline(args, directory, plan_path, material_path, dll, fragments, words_path, native, run, *, scope_materials=None):
    source = directory / "pipeline-source"; source.mkdir()
    build = directory / "pipeline-build"
    output, report = build / "final.exe", build / "final.json"
    def quote(path): return '"' + Path(path).resolve().as_posix() + '"'
    probe = ROOT / "tests/measurement" / ("scope_slot_probe.cpp" if scope_materials else "slot_probe.cpp")
    material_arguments = ""
    if scope_materials:
        material_arguments = " SCOPE_MATERIALS " + " ".join(f'"{index}={path.resolve().as_posix()}"'
            for index, path in scope_materials.items())
    def refresh_inputs():
        if scope_materials:
            from scope_slot_inputs import write_inputs
            write_inputs(words_path, plan_path, material_path, scope_materials)
        else: words_path.write_bytes(struct.pack("<8I", *material_fold(json.loads(material_path.read_text()))))
    cmake = ('cmake_minimum_required(VERSION 3.24)\nproject(reference_pipeline LANGUAGES CXX)\n'
        f'include({quote(ROOT / "cmake/ReferenceSlots.cmake")})\n'
        f'add_executable(raw {quote(probe)} ' +
        ' '.join(quote(path) for path in (*native, *args.backend)) + ')\n'
        'target_compile_features(raw PRIVATE cxx_std_17)\n'
        f'target_include_directories(raw PRIVATE {quote(ROOT / "src")} {quote(ROOT / "include")})\n'
        'target_link_libraries(raw PRIVATE bcrypt)\n'
        f'pyobf_native_reference_storage(raw {quote(plan_path)})\n'
        f'pyobf_native_finalize_references(final raw {quote(material_path)} {quote(output)} {quote(report)}\n'
        f'    TARGETS "{"22" * 16}={dll.resolve().as_posix()}" OBJECTS "2={fragments.resolve().as_posix()}"{material_arguments})\n')
    (source / "CMakeLists.txt").write_text(cmake)
    run([args.cmake, "-S", source, "-B", build, "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={args.ninja}",
        f"-DCMAKE_CXX_COMPILER={args.compiler}", f"-DPython3_EXECUTABLE={args.python}",
        f"-DCMAKE_INTERPROCEDURAL_OPTIMIZATION={'ON' if args.ipo else 'OFF'}"])
    command = [args.cmake, "--build", build, "--target", "final", "-j", "4"]
    run(command); run([output, words_path, dll, "1"])
    raw = build / "raw.exe"
    snapshot = {path: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).digest())
        for path in (raw, output, report, build / "raw.references/reference_slots.hpp",
            build / "raw.references/reference_slots.cpp")}
    unchanged = run(command)
    if "no work to do" not in unchanged.stdout or any(
            (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).digest()) != value for path, value in snapshot.items()):
        raise AssertionError("unchanged reference dependency chain rebuilt or changed bytes")
    # A private-material change reruns filling without changing the compiled image/storage.
    material = json.loads(material_path.read_text()); material["seed"] ^= 1
    material_path.write_text(json.dumps(material))
    refresh_inputs()
    run(command); run([output, words_path, dll, "1"])
    if hashlib.sha256(raw.read_bytes()).digest() != snapshot[raw][1]:
        raise AssertionError("late key material was fed back into code generation")
    if hashlib.sha256(output.read_bytes()).digest() == snapshot[output][1]:
        raise AssertionError("material dependency failed to refresh ciphertext")
    # An early identity change rebuilds header/storage and its observing consumer.
    value = json.loads(plan_path.read_text()); value["records"][0]["owner"] += 1
    plan_path.write_text(json.dumps(value)); refresh_inputs(); run(command); run([output, words_path, dll, "1"])
    if hashlib.sha256(raw.read_bytes()).digest() == snapshot[raw][1]:
        raise AssertionError("early identity dependency did not rebuild compiled expectations")
    stable = run(command)
    if "no work to do" not in stable.stdout: raise AssertionError("updated reference chain is not stable")
    # Do not allow a missing symbolic producer input to reuse old finalized output.
    fragments.rename(fragments.with_suffix(".missing"))
    run(command, succeeds=False)
    fragments.with_suffix(".missing").rename(fragments)
    if scope_materials:
        before_raw, before_final = raw.read_bytes(), output.read_bytes()
        path = next(iter(scope_materials.values()))
        previous = path.read_bytes(); path.write_bytes(bytes([previous[0] ^ 1]) + previous[1:])
        refresh_inputs(); run(command); run([output, words_path, dll, "1"])
        if raw.read_bytes() != before_raw or output.read_bytes() == before_final:
            raise AssertionError("late scoped material changed code or failed to refresh finalized data")
        path.rename(path.with_suffix(".missing"))
        try: run(command, succeeds=False)
        finally: path.with_suffix(".missing").rename(path)
        if "no work to do" not in run(command).stdout:
            raise AssertionError("restored scoped material chain is not stable")
    print("CMake early identity, late material, exact object dependency and no-change chains pass")
