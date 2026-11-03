"""Typed local-object, alias, lifetime and invocation-ownership fixtures."""

FUNCTIONS = ("local_values", "local_alias", "local_escape", "local_loop", "local_recursive",
             "local_reentrant", "local_atomic", "local_lifetime", "local_volatile")

SOURCE_IR = r'''
target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
%Pair = type { i32, double }
declare i32 @observe(ptr, ptr, i32)
declare i32 @call_again(ptr, i32)
declare void @llvm.lifetime.start.p0(ptr captures(none))
declare void @llvm.lifetime.end.p0(ptr captures(none))
define internal i32 @leaf(i32 %x) noinline { %r = add i32 %x, 1
ret i32 %r }
define i32 @local_values(i32 %x) noinline {
entry:
  %array = alloca [4 x i32], align 32
  %pair = alloca %Pair, align 16
  %vector = alloca <2 x i64>, align 16
  %bytes = alloca i8, i32 4, align 8
  %wide = alloca i128, align 16
  %function = alloca ptr, align 8
  store [4 x i32] zeroinitializer, ptr %array, align 32
  %element = getelementptr [4 x i32], ptr %array, i32 0, i32 2
  store i32 %x, ptr %element, align 8
  %a = load i32, ptr %element, align 8
  %field = getelementptr %Pair, ptr %pair, i32 0, i32 1
  store double 2.500000e+00, ptr %field, align 8
  %fp = load double, ptr %field, align 8
  %b = fptosi double %fp to i32
  store <2 x i64> <i64 3, i64 7>, ptr %vector, align 16
  %v = load <2 x i64>, ptr %vector, align 16
  %v0 = extractelement <2 x i64> %v, i32 0
  %v1 = extractelement <2 x i64> %v, i32 1
  %vsum = add i64 %v0, %v1
  %c = trunc i64 %vsum to i32
  %last = getelementptr i8, ptr %bytes, i32 3
  store i8 7, ptr %last, align 1
  %small = load i8, ptr %last, align 1
  %d = zext i8 %small to i32
  %extended = sext i32 %x to i128
  store i128 %extended, ptr %wide, align 16
  %read = load i128, ptr %wide, align 16
  %e = trunc i128 %read to i32
  store ptr @leaf, ptr %function, align 8
  %fn = load ptr, ptr %function, align 8
  %f = call i32 %fn(i32 5)
  %ab = add i32 %a, %b
  %cd = add i32 %c, %d
  %ef = add i32 %e, %f
  %sum = add i32 %ab, %cd
  %result = add i32 %sum, %ef
  ret i32 %result
}
define i32 @local_alias(i32 %x) noinline {
entry:
  %a = alloca i32, align 16
  %b = alloca i32, align 16
  store i32 %x, ptr %a, align 16
  %other = add i32 %x, 5
  store i32 %other, ptr %b, align 16
  %bit = and i32 %x, 1
  %even = icmp eq i32 %bit, 0
  %selected = select i1 %even, ptr %a, ptr %b
  br i1 %even, label %left, label %right
left:
  br label %join
right:
  br label %join
join:
  %merged = phi ptr [ %a, %left ], [ %b, %right ]
  %v = load i32, ptr %selected, align 16
  %w = load i32, ptr %merged, align 16
  %same = icmp eq ptr %selected, %merged
  %check = select i1 %same, i32 1, i32 -10000
  %sum = add i32 %v, %w
  %r = add i32 %sum, %check
  ret i32 %r
}
define i32 @local_escape(i32 %x) noinline {
entry:
  %a = alloca i32, align 64
  %b = alloca i32, align 16
  store i32 %x, ptr %a, align 64
  %observed = call i32 @observe(ptr %a, ptr %a, i32 %x)
  %value = load i32, ptr %a, align 64
  %different = icmp ne ptr %a, %b
  %check = select i1 %different, i32 1, i32 -10000
  %r = add i32 %value, %observed
  %result = add i32 %r, %check
  ret i32 %result
}
define i32 @local_loop(i32 %n) noinline {
entry:
  %index = alloca i32, align 4
  %sum = alloca i32, align 4
  store i32 0, ptr %index, align 4
  store i32 0, ptr %sum, align 4
  br label %check
check:
  %i = load i32, ptr %index, align 4
  %more = icmp slt i32 %i, %n
  br i1 %more, label %body, label %exit
body:
  %prior = load i32, ptr %sum, align 4
  %total = add i32 %prior, %i
  store i32 %total, ptr %sum, align 4
  %next = add i32 %i, 1
  store i32 %next, ptr %index, align 4
  br label %check
exit:
  %r = load i32, ptr %sum, align 4
  ret i32 %r
}
define i32 @local_recursive(i32 %depth) noinline {
entry:
  %saved = alloca i32, align 16
  store i32 %depth, ptr %saved, align 16
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %zero, label %next
zero:
  ret i32 0
next:
  %n = sub i32 %depth, 1
  %previous = call i32 @local_recursive(i32 %n)
  %current = load i32, ptr %saved, align 16
  %r = add i32 %previous, %current
  ret i32 %r
}
define i32 @local_reentrant(i32 %depth) noinline {
entry:
  %saved = alloca i32, align 16
  %expected = add i32 %depth, 41
  store i32 %expected, ptr %saved, align 16
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %zero, label %next
zero:
  ret i32 42
next:
  %n = sub i32 %depth, 1
  %previous = call i32 @call_again(ptr @local_reentrant, i32 %n)
  %current = load i32, ptr %saved, align 16
  %same = icmp eq i32 %current, %expected
  %r = add i32 %previous, 1
  %result = select i1 %same, i32 %r, i32 -10000
  ret i32 %result
}
define i32 @local_atomic(i32 %x) noinline {
entry:
  %value = alloca i32, align 4
  store atomic i32 %x, ptr %value seq_cst, align 4
  %prior = atomicrmw add ptr %value, i32 2 seq_cst, align 4
  %expected = add i32 %x, 2
  %next = add i32 %x, 4
  %pair = cmpxchg ptr %value, i32 %expected, i32 %next seq_cst seq_cst, align 4
  %succeeded = extractvalue {i32, i1} %pair, 1
  %read = load atomic i32, ptr %value seq_cst, align 4
  %r = select i1 %succeeded, i32 %read, i32 -10000
  ret i32 %r
}
define i32 @local_lifetime(i32 %x) noinline {
entry:
  %value = alloca i32, align 16
  call void @llvm.lifetime.start.p0(ptr %value)
  store i32 %x, ptr %value, align 16
  %v = load i32, ptr %value, align 16
  %r = add i32 %v, 3
  call void @llvm.lifetime.end.p0(ptr %value)
  ret i32 %r
}
define i32 @local_volatile(i32 %x) noinline {
entry:
  %value = alloca i32, align 16
  store volatile i32 %x, ptr %value, align 16
  %r = load volatile i32, ptr %value, align 16
  ret i32 %r
}
define i32 @folded_local(i32 %x) noinline {
entry:
  %value = alloca i32, align 4
  store i32 %x, ptr %value, align 4
  %r = load i32, ptr %value, align 4
  ret i32 %r
}
'''

HELPER = r'''
#include <cstdint>
extern "C" int observe(int *left,int *right,int expected){
    if(left!=right || (reinterpret_cast<std::uintptr_t>(left)&15u) || *left!=expected)return -10000;
    *left+=3;return 7;
}
extern "C" int call_again(int(*callback)(int),int depth){return callback(depth);}
'''

HARNESS = r'''
#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>
extern "C" {
int local_values(int),local_alias(int),local_escape(int),local_loop(int),local_recursive(int);
int local_reentrant(int),local_atomic(int),local_lifetime(int),local_volatile(int);
}
bool check(){
    for(int n=-20;n<=24;++n)
        if(local_values(n)!=2*n+25 || local_alias(n)!=2*n+((n&1)?11:1) || local_escape(n)!=n+11 ||
           local_atomic(n)!=n+4 || local_lifetime(n)!=n+3 || local_volatile(n)!=n)return false;
    for(int n=0;n<=16;++n)
        if(local_loop(n)!=n*(n-1)/2 || local_recursive(n)!=n*(n+1)/2 || local_reentrant(n)!=n+42)return false;
    return true;
}
int main(){
    if(!check())return 1;
    std::atomic<bool> good{true};std::vector<std::thread> workers;
    for(unsigned i=0;i<4;++i)workers.emplace_back([&]{for(unsigned j=0;j<32;++j)if(!check())good=false;});
    for(auto &worker:workers)worker.join();
    if(!good)return 2;std::puts("LOCALS_OK");
}
'''
