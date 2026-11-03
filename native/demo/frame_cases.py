"""Call-frame ABI/effect/recursive fixtures shared with reference-route tests."""

from reference_cases import SOURCE_IR as REFERENCE_IR, HARNESS as REFERENCE_HARNESS, HELPER

FUNCTIONS = ("calls", "abi", "recursive", "odd", "even", "tail_call", "framed_reentrant", "framed_loop", "framed_values")

SOURCE_IR = REFERENCE_IR + r'''
define internal i32 @callback_adapter(ptr %fn, i32 %depth) {
entry:
  %r = call i32 @invoke_callback(ptr %fn, i32 %depth)
  ret i32 %r
}
define i32 @framed_reentrant(i32 %depth) noinline {
entry:
  %done = icmp eq i32 %depth, 0
  br i1 %done, label %zero, label %next
zero:
  ret i32 42
next:
  %n = sub i32 %depth, 1
  %prior = call i32 @callback_adapter(ptr @framed_reentrant, i32 %n)
  %r = add i32 %prior, 1
  ret i32 %r
}
define i32 @folded_call(i32 %x) noinline {
entry:
  %unused = call i32 @increment(i32 %x)
  ret i32 %x
}
define i32 @framed_loop(i32 %n) noinline {
entry:
  %positive = icmp sgt i32 %n, 0
  br i1 %positive, label %loop, label %zero
zero:
  ret i32 0
loop:
  %index = phi i32 [ 0, %entry ], [ %next, %loop ]
  %sum = phi i32 [ 0, %entry ], [ %total, %loop ]
  %item = call i32 @increment(i32 %index)
  %total = add i32 %sum, %item
  %next = add i32 %index, 1
  %done = icmp eq i32 %next, %n
  br i1 %done, label %exit, label %loop
exit:
  ret i32 %total
}
define internal %Pair @pair_echo(%Pair %value) noinline {
entry:
  ret %Pair %value
}
define internal <2 x i64> @vector_echo(<2 x i64> %value) noinline {
entry:
  ret <2 x i64> %value
}
define internal void @nothing() noinline {
entry:
  ret void
}
define i32 @framed_values(i32 %n) noinline {
entry:
  %p = insertvalue %Pair {i32 0, double 0x8000000000000000}, i32 %n, 0
  %pair = call %Pair @pair_echo(%Pair %p)
  %number = extractvalue %Pair %pair, 0
  %fp = extractvalue %Pair %pair, 1
  %bits = bitcast double %fp to i64
  %negative_zero = icmp eq i64 %bits, -9223372036854775808
  %wide = sext i32 %n to i64
  %v = insertelement <2 x i64> <i64 0, i64 9>, i64 %wide, i32 0
  %vector = call <2 x i64> @vector_echo(<2 x i64> %v)
  %a = extractelement <2 x i64> %vector, i32 0
  %b = extractelement <2 x i64> %vector, i32 1
  %sum = add i64 %a, %b
  %truncated = trunc i64 %sum to i32
  %result = add i32 %number, %truncated
  call void @nothing()
  %checked = select i1 %negative_zero, i32 %result, i32 -10000
  ret i32 %checked
}
'''

HARNESS = REFERENCE_HARNESS.replace('extern "C" {',
    'extern "C" {\nint framed_reentrant(int), framed_loop(int), framed_values(int);').replace(
    "if(recursive(n)!=n", "if(framed_loop(n)!=n*(n-1)/2+7*n || framed_values(n)!=2*n+9 || "
    "framed_reentrant(n)!=n+42 || recursive(n)!=n")
