"""Exercise external adapters in the actual Windows semantic memory backend."""

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from check_cff_transition_depth import run


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--imports", action="store_true")
    parser.add_argument("--hybrid", action="store_true")
    parser.add_argument("--hybrid-frames", action="store_true")
    args = parser.parse_args()
    if args.hybrid_frames and not args.hybrid: parser.error("hybrid frames require the hybrid profile")
    if args.hybrid and args.imports and not args.hybrid_frames:
        parser.error("hybrid imported adapters require --hybrid-frames")
    native = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        user, user_ir, backend_ir, combined, output = (directory / name for name in
            ("user.cpp", "user.ll", "backend.ll", "combined.ll", "output.ll"))
        user.write_text('''#include "pyobfuscator_native/system_ops.hpp"
extern "C" int backend_external(int input) {
    auto *data = static_cast<unsigned char *>(PYOBF_NATIVE_ALLOCATE(128));
    if (data == nullptr) return -1;
    for (unsigned index = 0; index < 128; ++index) data[index] = static_cast<unsigned char>(input + index);
    const auto saved = data[17];
    PYOBF_NATIVE_ERASE(data, 128);
    int sum = 0;
    for (unsigned index = 0; index < 128; ++index) sum += data[index];
    PYOBF_NATIVE_RELEASE(data);
    return sum == 0 ? saved : -2;
}
''', encoding="utf-8")
        for source, destination in ((user, user_ir), (native / "backends/windows_user/operations/memory.cpp", backend_ir)):
            run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-I", str(native / "include"),
                 "-S", "-emit-llvm", str(source), "-o", str(destination)])
        run([str(args.llvm_link), "-S", str(user_ir), str(backend_ir), "-o", str(combined)])
        names = [match[1] for match in re.finditer(r"^define[^\n]* @([^\s(]+)\(", combined.read_text(), re.M)
                 if "platform" in match[1] and ("allocate" in match[1] or "release" in match[1])]
        if len(names) != 2: raise AssertionError("actual backend allocate/release definitions missing")
        config, report = directory / "recipe.json", directory / "report.json"
        components = {"external-calls": "required", "call-preparation": "required"}
        if args.imports: components["import-routes"] = "required"
        config.write_text(json.dumps({"schema_version": 1, "functions": {
            name: {"components": components} for name in names}}), encoding="utf-8")
        # The default C++ frontend emits noexcept terminate cleanup around these C APIs.
        # Keep that current D1b boundary visible rather than silently treating it as covered.
        result = run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
            f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", "-verify-each", "-S", str(combined), "-o", str(output)], succeeds=False)
        failures = [row.get("reason", "") for row in json.loads(report.read_text())["functions"] if row.get("selected")]
        if len(failures) != 2 or any("supports branches, switches, and returns only" not in reason for reason in failures) or output.exists():
            raise AssertionError("default frontend EH boundary changed; update the D1b coverage contract")
        if args.hybrid:
            config.write_text(json.dumps({"schema_version": 1, "functions": {
                name: {"coverage": "hybrid-eh", "components": components if args.hybrid_frames else {}}
                for name in names}}), encoding="utf-8")
        else:
            run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-fno-exceptions", "-I", str(native / "include"),
                 "-S", "-emit-llvm", str(native / "backends/windows_user/operations/memory.cpp"), "-o", str(backend_ir)])
            run([str(args.llvm_link), "-S", str(user_ir), str(backend_ir), "-o", str(combined)])
        try:
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff",
                f"-pyobf-cff-config={config}", f"-pyobf-cff-report={report}", "-verify-each", "-S", str(combined), "-o", str(output)])
        except AssertionError as error:
            reasons = [(row["function"], row.get("reason")) for row in json.loads(report.read_text())["functions"]
                       if row.get("selected") and row["status"] != "transformed"] if report.exists() else []
            raise AssertionError(f"actual backend coverage failures: {reasons}") from error
        text = output.read_text()
        if "declare dllimport" not in text or not all(name in text for name in ("HeapAlloc", "HeapFree", "GetProcessHeap")):
            raise AssertionError("ordinary Windows imported API ownership changed")
        harness = directory / "harness.cpp"
        harness.write_text('''#include <thread>
#include <atomic>
#include <cstdio>
extern "C" int backend_external(int);
int main(){ std::atomic<bool> ok{true}; std::thread threads[4];
for(auto &thread:threads)thread=std::thread([&]{for(int n=0;n<40;++n)if(backend_external(n)!=n+17)ok=false;});
for(auto &thread:threads)thread.join(); if(!ok)return 1; std::puts("BACKEND_EXTERNAL_OK"); }
''', encoding="utf-8")
        binary = directory / "test.exe"
        for source in (combined, output):
            run([str(args.compiler), str(source), str(harness), "-o", str(binary)])
            if "BACKEND_EXTERNAL_OK" not in run([str(binary)]).stdout: raise AssertionError("actual protected backend memory behavior failed")
        image = directory / "test.dll"
        run([str(args.compiler), "-shared", str(output), "-o", str(image)])
        run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])


if __name__ == "__main__":
    main()
