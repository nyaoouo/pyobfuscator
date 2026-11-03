"""A live noinline target whose unused constant return O2 can erase from its ABI."""

SOURCE = '''target triple = "x86_64-w64-windows-gnu"
target datalayout = "e-m:w-p:64:64-i64:64-n8:16:32:64-S128"
@llvm.compiler.used = appending global [1 x ptr] [ptr @unrelated], section "llvm.metadata"
declare i32 @__gxx_personality_seh0(...)
declare void @throw_signal(i32)
declare void @cleanup_effect() nounwind

define internal i32 @unrelated(i32 %x) noinline {
  ret i32 %x
}

define internal i32 @abi_leaf(i32 %mode) noinline {
  call void @throw_signal(i32 %mode)
  ret i32 11
}

define i32 @abi_owner(i32 %mode) personality ptr @__gxx_personality_seh0 {
entry:
  %result = invoke i32 @abi_leaf(i32 %mode) to label %normal unwind label %pad
normal:
  %sum = add i32 %result, 7
  ret i32 %sum
pad:
  %exception = landingpad { ptr, i32 } cleanup
  call void @cleanup_effect()
  resume { ptr, i32 } %exception
}
'''

HARNESS = '''#include <cstdio>
int effects = 0;
extern "C" int abi_owner(int);
extern "C" void throw_signal(int mode) { if (mode != 0) throw -mode; }
extern "C" void cleanup_effect() noexcept { ++effects; }
int main() {
    if (abi_owner(0) != 18) return 1;
    for (int mode = 1; mode < 4; ++mode) {
        try { abi_owner(mode); return 2; }
        catch (int error) { if (error != -mode) return 3; }
    }
    if (effects != 3) return 4;
    std::puts("ABI_RETENTION_OK");
}
'''
