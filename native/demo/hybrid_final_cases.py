"""An explicit EH boundary whose post-CFF optimization can remove dispatcher work."""

ERASURE_SOURCE = '''target triple = "x86_64-w64-windows-gnu"
target datalayout = "e-m:w-p:64:64-i64:64-n8:16:32:64-S128"
declare i32 @__gxx_personality_seh0(...)
define internal i32 @known_target(i32 %x) noinline {
entry:
  %times = mul i32 %x, 3
  %value = add i32 %times, 7
  ret i32 %value
}
define i32 @hybrid_erased(i32 %x) personality ptr @__gxx_personality_seh0 {
entry:
  %value = invoke i32 @known_target(i32 %x) to label %normal unwind label %pad
normal:
  ret i32 %value
pad:
  %exception = landingpad { ptr, i32 } cleanup
  resume { ptr, i32 } %exception
}
'''

ERASURE_HARNESS = '''#include <cstdio>
extern "C" int hybrid_erased(int);
int main() {
    for (int x = -30; x <= 30; ++x) if (hybrid_erased(x) != x * 3 + 7) return 1;
    std::puts("ERASURE_OK");
}
'''
