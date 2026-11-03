"""Source fixtures for the typed archive compiler handoff, separate from its checks."""

LAYOUT = 'e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128'
HEADER = f'target datalayout = "{LAYOUT}"\ntarget triple = "x86_64-w64-windows-gnu"\n'

POSITIVE = HEADER + r'''
@secret = private constant [7 x i8] c"A\00B\FFC!\00", align 64
@empty = private constant [0 x i8] zeroinitializer, align 4
@wide = private constant [3 x i16] [i16 55296, i16 90, i16 0], align 8
@number = private constant i33 8589934591, align 16
@nan = private constant double 0x7FF8123456789ABC, align 8
@zeros = private constant [2 x i32] zeroinitializer, align 8
@nested = private constant [2 x [2 x i8]] [[2 x i8] c"AB", [2 x i8] c"CD"], align 4
@live = internal global i32 9

declare void @consume(ptr)

define ptr @pointer(i1 %pick) {
entry:
  br i1 %pick, label %yes, label %no
yes:
  br label %merge
no:
  br label %merge
merge:
  %p = phi ptr [getelementptr ([7 x i8], ptr @secret, i64 0, i64 2), %yes], [@empty, %no]
  ret ptr %p
}

define i64 @data() {
entry:
  call void @consume(ptr @secret)
  call void @consume(ptr @wide)
  call void @consume(ptr @zeros)
  call void @consume(ptr @nested)
  %x = load i33, ptr @number, align 16, !invariant.load !0
  %y = zext i33 %x to i64
  %z = load double, ptr @nan, align 8
  %bits = bitcast double %z to i64
  %result = xor i64 %y, %bits
  ret i64 %result
}

define double @floating(i1 %pick) {
entry:
  br i1 %pick, label %yes, label %no
yes:
  br label %merge
no:
  br label %merge
merge:
  %x = phi double [0x8000000000000000, %yes], [0x7FF8000000000011, %no]
  ret double %x
}

define i32 @pure() nofree nosync willreturn speculatable memory(none) {
entry:
  ret i32 7
}

define i32 @caller() nofree nosync willreturn memory(none) {
entry:
  %x = call i32 @pure() nofree nosync willreturn memory(none)
  %live = load i32, ptr @live
  %sum = add i32 %x, %live
  ret i32 %sum
}

!0 = !{}
'''

FUNCTIONS = 'pointer,data,floating,pure,caller'
GLOBAL_BYTES = ['410042ff432100', '', '00d85a000000', 'ffffffff01000000',
                'bc9a78563412f87f', '0000000000000000', '41424344']


def global_case(declaration: str, extra: str = '', pointer: str = '@s') -> str:
    return HEADER + declaration + '\n' + extra + f'\ndefine ptr @f() {{ ret ptr {pointer} }}\n'


NEGATIVE = [
    (global_case('@s = constant i32 1'), 'local immutable defined'),
    (global_case('@s = private constant i32 1', 'define i32 @other() { %x = load i32, ptr @s\n ret i32 %x }'),
     'outside selected'),
    (global_case('@s = private constant i32 1', '@holder = private constant ptr @s'), 'global initializer'),
    (global_case('@s = private constant i32 1', '@a = internal alias i32, ptr @s', '@a'), 'alias'),
    (global_case('@s = internal thread_local constant i32 1'), 'TLS'),
    (global_case('@s = private constant i32 1, section "custom"'), 'section'),
    (global_case('@s = private constant i32 1, align 8192'), 'alignment'),
    (global_case('@s = private constant [2 x i8] [i8 1, i8 undef]'), 'undef or poison'),
    (global_case('@s = private constant [2 x i8] [i8 1, i8 poison]'), 'undef or poison'),
    (global_case('@s = private constant ptr null'), 'fixed arrays only'),
    (global_case('@s = private constant {i8, i32} {i8 1, i32 2}'), 'fixed arrays only'),
    (global_case('@s = private constant [16777217 x i8] zeroinitializer'), 'byte budget'),
    (global_case('@s = private constant [999999999 x [0 x i8]] zeroinitializer'), 'zero-sized'),
    (HEADER + 'define <2 x i32> @f() { ret <2 x i32> <i32 1, i32 2> }', 'fixed arrays only'),
    (HEADER + 'define <2 x i32> @f() { ret <2 x i32> zeroinitializer }', 'fixed arrays only'),
    (HEADER + 'define i256 @f() { ret i256 9 }', 'i1 through i128'),
    (global_case('@s = private constant i32 1', 'module asm "# opaque access"'), 'assembly'),
    (global_case('@s = private constant i32 1', 'define void @asm_user() { call void asm sideeffect "", ""()\n ret void }'),
     'assembly'),
    (HEADER + '''@llvm.global_ctors = appending global [1 x {i32, ptr, ptr}]
        [{i32, ptr, ptr} {i32 65535, ptr @boot, ptr null}]
        define void @boot() { %v = call i32 @f()\n ret void }
        define i32 @f() { ret i32 7 }''', 'constructor'),
    (HEADER + 'define i32 @DllMain() { %v = call i32 @f()\n ret i32 %v }\ndefine i32 @f() { ret i32 7 }',
     'loader entry'),
]
