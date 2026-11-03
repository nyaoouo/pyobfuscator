target triple = "x86_64-w64-windows-gnu"
define dllexport i32 @owned_root(i32 %value) {
entry:
  %a = call i32 @ordinary_callee(i32 %value)
  %b = call i32 @external_target(i32 %a)
  %condition = icmp ult i32 %value, 31
  br i1 %condition, label %small, label %large
small:
  %small_result = xor i32 %b, 17
  ret i32 %small_result
large:
  %large_result = add i32 %b, %value
  ret i32 %large_result
}
define dllexport i32 @ordinary_callee(i32 %value) noinline {
entry:
  %a = mul i32 %value, 3
  %b = xor i32 %a, 85
  ret i32 %b
}
declare i32 @external_target(i32)
