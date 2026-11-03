"""Explicit invoke-result and shared-pad PHIs for the hybrid boundary regression."""

SOURCE = '''target triple = "x86_64-w64-windows-gnu"
target datalayout = "e-m:w-p:64:64-i64:64-n8:16:32:64-S128"
declare i32 @__gxx_personality_seh0(...)
declare i32 @throw_or_return(i32)
@cleanup_count = external global i32
define i32 @hybrid_phi(i1 zeroext %left, i32 %x) personality ptr @__gxx_personality_seh0 {
entry:
  br i1 %left, label %a, label %b
a:
  %one = invoke i32 @throw_or_return(i32 %x) to label %join unwind label %pad
b:
  %two = invoke i32 @throw_or_return(i32 %x) to label %join unwind label %pad
join:
  %value = phi i32 [ %one, %a ], [ %two, %b ]
  ret i32 %value
pad:
  %amount = phi i32 [ 2, %a ], [ 5, %b ]
  %exception = landingpad { ptr, i32 } cleanup
  %old = load i32, ptr @cleanup_count
  %next = add i32 %old, %amount
  store i32 %next, ptr @cleanup_count
  resume { ptr, i32 } %exception
}
'''

HARNESS = '''#include <cstdio>
extern "C" {
int cleanup_count = 0;
__attribute__((noinline)) int throw_or_return(int x) { if(x<0)throw x; return x*3+1; }
int hybrid_phi(bool, int);
}
int main() {
for(int flag=0;flag<2;++flag)for(int x=-4;x<=4;++x) {
cleanup_count=0;int value;
try {value=hybrid_phi(flag!=0,x);}catch(int error){value=100+error;}
if(cleanup_count!=(x<0?(flag?2:5):0))return 1;
std::printf("%d:%d:%d:%d\\n",flag,x,value,cleanup_count);
}}
'''

SWITCH_SOURCE = SOURCE.replace(
    "define i32 @hybrid_phi(i1 zeroext %left, i32 %x)", "define i32 @hybrid_switch(i32 %left, i32 %x)"
).replace(
    "  br i1 %left, label %a, label %b",
    "  switch i32 %left, label %b [ i32 -2, label %a i32 1, label %a ]"
).replace(
    "  ret i32 %value",
    """  switch i32 %value, label %other [ i32 1, label %edge i32 7, label %edge ]
edge:
  %edge_value = add i32 %value, 20
  ret i32 %edge_value
other:
  %other_value = add i32 %value, 30
  ret i32 %other_value"""
)

SWITCH_HARNESS = '''#include <cstdio>
extern "C" {
int cleanup_count = 0;
__attribute__((noinline)) int throw_or_return(int x) { if (x < 0) throw x; return x * 3 + 1; }
int hybrid_switch(int, int);
}
int main() {
    for (int flag = -3; flag <= 3; ++flag) for (int x = -4; x <= 4; ++x) {
        cleanup_count = 0;
        int value;
        try { value = hybrid_switch(flag, x); } catch (int error) { value = 100 + error; }
        const auto expected = x < 0 ? 100 + x : x * 3 + 1 + (x == 0 || x == 2 ? 20 : 30);
        const auto effects = x < 0 ? (flag == -2 || flag == 1 ? 2 : 5) : 0;
        if (value != expected || cleanup_count != effects) return 1;
        std::printf("%d:%d:%d:%d%c", flag, x, value, cleanup_count, 10);
    }
}
'''

FUNCLET = '''target triple = "x86_64-w64-windows-gnu"
declare i32 @__CxxFrameHandler3(...)
declare i32 @throw_or_return(i32)
define i32 @hybrid_phi(i1 %left, i32 %x) personality ptr @__CxxFrameHandler3 {
entry:
  %r = invoke i32 @throw_or_return(i32 %x) to label %returned unwind label %dispatch
returned:
  ret i32 %r
dispatch:
  %pad = catchswitch within none [label %catch] unwind to caller
catch:
  %token = catchpad within %pad [ptr null, i32 64, ptr null]
  catchret from %token to label %done
done:
  ret i32 1
}
'''
