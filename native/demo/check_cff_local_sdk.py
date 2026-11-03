"""Link real SDK/user/backend source units and execute indexed local object routes."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from check_cff_transition_depth import run


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "llvm_link", "objdump", "linked_checker", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        user, harness = directory / "user.cpp", directory / "harness.cpp"
        user.write_text('''#include "pyobfuscator_native/sdk.hpp"
using namespace pyobfuscator::native;
static void callback(const DetectionReport &report,void *context){
    auto *values=static_cast<int*>(context);
    values[1]=report.status==DetectionStatus::unavailable?values[0]+17:-10000;
}
extern "C" int user_entry(int value){
    int values[2]={value,0};
    const auto report=inspect_current_process(callback,values);
    return report.status==DetectionStatus::unavailable?values[1]:-10000;
}
''', encoding="utf-8")
        harness.write_text('''#include <cstdio>
extern "C" int user_entry(int);
int main(){for(int n=-20;n<40;++n)if(user_entry(n)!=n+17)return 1;
std::puts("SDK_LOCALS_OK");}
''', encoding="utf-8")
        units = []
        for index, path in enumerate((root / "src/sdk.cpp", root / "backends/windows_user/sdk_environment.cpp",
                                      root / "backends/windows_user/operations/atomic.cpp", user)):
            output = directory / f"unit-{index}.ll"
            run([str(args.compiler), "-std=c++17", "-O0", "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
                "-I", str(root / "include"), "-I", str(root / "src"), str(path), "-o", str(output)])
            units.append(output)
        source, output, config, report = (directory / name for name in ("combined.ll", "protected.ll", "recipe.json", "report.json"))
        run([str(args.llvm_link), "-S", *map(str, units), "-o", str(source)])
        baseline, binary, image = directory / "plain.exe", directory / "protected.exe", directory / "protected.dll"
        run([str(args.compiler), str(source), str(harness), "-o", str(baseline)])
        expected = run([str(baseline)]).stdout
        config.write_text(json.dumps({"schema_version": 1,
            "markers": {"pyobf.native.sdk": {"components": {"indexed-locals": "optional", "reference-routes": "optional"}}},
            "functions": {"user_entry": {"components": {"indexed-locals": "required"}}}}), encoding="utf-8")
        run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff", f"-pyobf-cff-config={config}",
            f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source), "-o", str(output)])
        rows = json.loads(report.read_text())["functions"]
        applied = {row["function"]: next((item["applied"] for item in row.get("components", []) if item["component"] == "indexed-locals"), 0)
            for row in rows if row["selected"]}
        if not applied.get("user_entry") or not any(count for name, count in applied.items() if "inspect_current_process" in name):
            raise AssertionError("linked SDK/user objects were not both protected by indexed locals")
        run([str(args.compiler), str(output), str(harness), "-o", str(binary)])
        if run([str(binary)]).stdout != expected: raise AssertionError("SDK callback/report or user stack objects changed")
        run([str(args.compiler), "-shared", str(output), "-o", str(image)])
        run([os.sys.executable, str(args.linked_checker), str(args.objdump), str(image), str(report)])


if __name__ == "__main__":
    main()
