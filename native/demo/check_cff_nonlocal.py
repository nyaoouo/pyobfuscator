"""Reject known nonlocal state resumption before whole/region CFF mutates a function."""

import argparse
import json
import tempfile
from pathlib import Path

from check_cff_transition_depth import run


LAYOUT = 'target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\n'
REGION = '''define i32 @region_owner(i1 %flag, i32 %x) {
entry:
  BEFORE
  br label %a
a:
  br i1 %flag, label %b, label %c
b:
  br label %join
c:
  br label %join
join:
  br label %out
out:
  ret i32 %x
}
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("compiler", "opt", "plugin", "build_dir"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(dir=args.build_dir) as temporary:
        directory = Path(temporary)
        source, output, report = (directory / name for name in ("source.ll", "output.ll", "report.json"))

        def transform(name: str, *, region: bool = False, succeeds: bool = False, reason: str = "returns-twice"):
            run([str(args.opt), "-passes=verify", "-disable-output", str(source)])
            output.unlink(missing_ok=True); report.unlink(missing_ok=True)
            selection = f"-pyobf-cff-region={name}:a:out" if region else f"-pyobf-cff-function={name}"
            run([str(args.opt), f"-load-pass-plugin={args.plugin}", "-passes=pyobf-native-cff", selection,
                 f"-pyobf-cff-report={report}", "-verify-each", "-S", str(source), "-o", str(output)], succeeds=succeeds)
            row = next(row for row in json.loads(report.read_text())["functions"] if row["function"] == name)
            if succeeds:
                if row["status"] != "transformed": raise AssertionError("ordinary control was not transformed")
            elif output.exists() or row["status"] != "unsupported" or reason not in row.get("reason", ""):
                raise AssertionError(f"unsafe control was emitted, credited or misclassified: {row}")

        fixture = Path(__file__).with_name("nonlocal_fixture.cpp")
        run([str(args.compiler), "-std=c++17", "-O1", "-fno-inline", "-S", "-emit-llvm", str(fixture), "-o", str(source)])
        if "returns_twice" not in source.read_text(): raise AssertionError("real setjmp fixture lost its control attribute")
        baseline = directory / "baseline.exe"
        run([str(args.compiler), str(source), "-o", str(baseline)])
        if run([str(baseline)]).stdout != "NONLOCAL_OK\n": raise AssertionError("legal original nonlocal fixture failed")
        transform("resume_case")

        cases = (
            ("target", '''declare i32 @twice(i32) returns_twice
define i32 @f(i32 %x) { %r = call i32 @twice(i32 %x)
ret i32 %r }
''', "returns-twice"),
            ("call-site", '''define i32 @f(ptr %fn, i32 %x) { %r = call i32 %fn(i32 %x) returns_twice
ret i32 %r }
''', "returns-twice"),
            ("function", 'define i32 @f(i32 %x) returns_twice { ret i32 %x }\n', "returns-twice"),
            ("alias", '''@aliased = alias i32 (i32), ptr @target
define i32 @target(i32 %x) returns_twice { ret i32 %x }
define i32 @f(i32 %x) { %r = call i32 @aliased(i32 %x)
ret i32 %r }
''', "returns-twice"),
            ("sjlj-save", '''declare i32 @llvm.eh.sjlj.setjmp(ptr)
define i32 @f(ptr %buffer) { %r = call i32 @llvm.eh.sjlj.setjmp(ptr %buffer)
ret i32 %r }
''', "SJLJ"),
            ("sjlj-restore", '''declare void @llvm.eh.sjlj.longjmp(ptr)
define void @f(ptr %buffer) { call void @llvm.eh.sjlj.longjmp(ptr %buffer)
unreachable }
''', "SJLJ"),
            ("coroutine", '''declare token @llvm.coro.id(i32, ptr, ptr, ptr)
define void @f() { %id = call token @llvm.coro.id(i32 0, ptr null, ptr null, ptr null)
ret void }
''', "coroutine"))
        for label, text, reason in cases:
            source.write_text(LAYOUT + text, encoding="utf-8")
            transform("f", reason=reason)

        for declaration, call, reason in (
                ("declare i32 @twice(i32) returns_twice", "%r = call i32 @twice(i32 %x)", "returns-twice"),
                ("declare token @llvm.coro.id(i32, ptr, ptr, ptr)",
                 "%id = call token @llvm.coro.id(i32 0, ptr null, ptr null, ptr null)", "coroutine")):
            source.write_text(LAYOUT + declaration + '\n' + REGION.replace("BEFORE", call), encoding="utf-8")
            transform("region_owner", region=True, reason=reason)

        # Function spelling is not a semantic blacklist, and unselected code is not selected scope.
        source.write_text(LAYOUT + '''define internal i32 @setjmp_like(i32 %x) { %r = add i32 %x, 1
ret i32 %r }
define i32 @unselected(i32 %x) returns_twice { ret i32 %x }
define i32 @ordinary(i32 %x) {
entry:
  %r = call i32 @setjmp_like(i32 %x)
  %negative = icmp slt i32 %x, 0
  br i1 %negative, label %minus, label %plus
minus:
  %m = sub i32 %r, 2
  ret i32 %m
plus:
  %p = add i32 %r, 9
  ret i32 %p
}
''' + REGION.replace("BEFORE", ""), encoding="utf-8")
        transform("ordinary", succeeds=True)
        harness = directory / "harness.cpp"
        harness.write_text('''extern "C" int ordinary(int);
int main(){for(int x=-20;x<20;++x)if(ordinary(x)!=(x<0?x-1:x+10))return 1;}
''', encoding="utf-8")
        binary = directory / "test.exe"
        run([str(args.compiler), str(output), str(harness), "-o", str(binary)]); run([str(binary)])
        transform("region_owner", region=True, succeeds=True)


if __name__ == "__main__":
    main()
