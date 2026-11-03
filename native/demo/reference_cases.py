"""Independent executable fixtures for state-bound native function references."""

from __future__ import annotations


FUNCTIONS = ("calls", "abi", "recursive", "odd", "even", "callback", "choose", "phi",
             "returned", "same_address", "address_bits", "save_address", "tail_call")

SOURCE_IR = r'''
target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
%Pair = type { i32, double }
@global_callback = global ptr @increment
declare i32 @invoke_callback(ptr, i32)
define available_externally i32 @aaa_unemitted() {
entry:
  ret i32 13
}
define i32 @increment(i32 %x) noinline {
entry:
  %r = add i32 %x, 7
  ret i32 %r
}
define i32 @decrement(i32 %x) noinline {
entry:
  %r = sub i32 %x, 3
  ret i32 %r
}
define internal i32 @touch(ptr %p, i32 %x) noinline {
entry:
  %old = load i32, ptr %p
  %next = add i32 %old, %x
  store i32 %next, ptr %p
  ret i32 %old
}
define internal double @floating(double %x, double %y) noinline {
entry:
  %r = fadd double %x, %y
  ret double %r
}
define internal fastcc signext i32 @fast(i32 signext %x) noinline {
entry:
  %r = mul i32 %x, 3
  ret i32 %r
}
define internal void @aggregate(ptr noalias sret(%Pair) align 8 %out,
                                ptr byval(%Pair) align 8 %in) noinline {
entry:
  %x = load %Pair, ptr %in, align 8
  store %Pair %x, ptr %out, align 8
  ret void
}
define i32 @calls(i32 %x, ptr %p) noinline {
entry:
  %a = call i32 @touch(ptr %p, i32 %x)
  %b = call i32 @touch(ptr %p, i32 5)
  %c = call i32 @increment(i32 %a)
  %d = sub i32 %b, %c
  ret i32 %d
}
define i32 @abi(i32 %x) noinline {
entry:
  %in = alloca %Pair, align 8
  %out = alloca %Pair, align 8
  store %Pair { i32 13, double 2.500000e+00 }, ptr %in, align 8
  call void @aggregate(ptr noalias sret(%Pair) align 8 %out, ptr byval(%Pair) align 8 %in)
  %v = load i32, ptr %out, align 8
  %fp = call double @floating(double 2.500000e+00, double 4.500000e+00)
  %f = fptosi double %fp to i32
  %s = call fastcc signext i32 @fast(i32 signext %x)
  %a = add i32 %v, %f
  %r = add i32 %a, %s
  ret i32 %r
}
define i32 @recursive(i32 %depth) noinline {
entry:
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %zero, label %next
zero:
  ret i32 0
next:
  %n = sub i32 %depth, 1
  %prior = call i32 @recursive(i32 %n)
  %r = add i32 %prior, 1
  ret i32 %r
}
define i32 @odd(i32 %depth) noinline {
entry:
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %zero, label %next
zero:
  ret i32 0
next:
  %n = sub i32 %depth, 1
  %r = call i32 @even(i32 %n)
  ret i32 %r
}
define i32 @even(i32 %depth) noinline {
entry:
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %zero, label %next
zero:
  ret i32 1
next:
  %n = sub i32 %depth, 1
  %r = call i32 @odd(i32 %n)
  ret i32 %r
}
define i32 @callback(i32 %depth) noinline {
entry:
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %zero, label %next
zero:
  ret i32 42
next:
  %n = sub i32 %depth, 1
  %prior = call i32 @invoke_callback(ptr @callback, i32 %n)
  %r = add i32 %prior, 1
  ret i32 %r
}
define ptr @choose(i1 %flag) noinline {
entry:
  %p = select i1 %flag, ptr @increment, ptr @decrement
  ret ptr %p
}
define ptr @phi(i32 %iterations) noinline {
entry:
  br label %loop
loop:
  %n = phi i32 [ %iterations, %entry ], [ %next, %again ]
  %p = phi ptr [ @increment, %entry ], [ @decrement, %again ]
  %done = icmp eq i32 %n, 0
  br i1 %done, label %exit, label %again
again:
  %next = sub i32 %n, 1
  br label %loop
exit:
  ret ptr %p
}
define ptr @returned(i1 %flag) noinline {
entry:
  br i1 %flag, label %yes, label %no
yes:
  ret ptr @increment
no:
  ret ptr @decrement
}
define i1 @same_address() noinline {
entry:
  %same = icmp eq ptr @increment, @increment
  ret i1 %same
}
define i64 @address_bits() noinline {
entry:
  %bits = ptrtoint ptr @increment to i64
  ret i64 %bits
}
define void @save_address(ptr %out) noinline {
entry:
  store ptr @increment, ptr %out
  ret void
}
define i32 @tail_call(i32 %x) noinline {
entry:
  %r = tail call i32 @increment(i32 %x)
  ret i32 %r
}
define i1 @folded() noinline {
entry:
  %same = icmp eq ptr @increment, @increment
  ret i1 %same
}
define i32 @variadic_target(i32 %x, ...) {
entry:
  ret i32 %x
}
define i32 @variadic_use(i32 %x) {
entry:
  %r = call i32 (i32, ...) @variadic_target(i32 %x)
  ret i32 %r
}
define i32 @musttail_use(i32 %x) {
entry:
  %r = musttail call i32 @increment(i32 %x)
  ret i32 %r
}
define i32 @bundled(i32 %x) {
entry:
  %r = call i32 @increment(i32 %x) [ "deopt"(i32 0) ]
  ret i32 %r
}
define void @nested(ptr %out) {
entry:
  store [2 x ptr] [ptr @increment, ptr @decrement], ptr %out
  ret void
}
'''

HELPER = r'''
extern "C" int invoke_callback(int (*fn)(int), int n) { return fn(n); }
'''

HARNESS = r'''
#include <cstdint>
#include <cstdio>
#include <thread>
#include <atomic>
using Fn = int(*)(int);
extern "C" {
int calls(int, int*), abi(int), recursive(int), odd(int), even(int), callback(int), tail_call(int);
int increment(int), decrement(int);
Fn choose(bool), phi(int), returned(bool);
bool same_address();
std::uintptr_t address_bits();
void save_address(Fn*);
extern Fn global_callback;
}
bool check(int n) {
    int value=11;
    if(calls(n,&value)!=n-7 || value!=n+16 || abi(n)!=20+3*n) return false;
    if(recursive(n)!=n || callback(n)!=n+42 || even(n)!=(n%2==0) || odd(n)!=(n%2!=0)) return false;
    if(choose(true)!=increment || choose(false)!=decrement || returned(true)!=increment ||
       returned(false)!=decrement || phi(0)!=increment || phi(n+1)!=decrement) return false;
    Fn p=nullptr; save_address(&p);
    return p==increment && same_address() && address_bits()==reinterpret_cast<std::uintptr_t>(increment) &&
           global_callback==increment && tail_call(n)==n+7;
}
int main() {
    for(int n=0;n<20;++n) if(!check(n)) return 1;
    std::atomic<bool> ok{true};
    std::thread threads[4];
    for(auto &thread:threads) thread=std::thread([&]{for(int n=0;n<20;++n) if(!check(n)) ok=false;});
    for(auto &thread:threads) thread.join();
    if(!ok) return 2;
    std::puts("references verified");
    return 0;
}
'''
