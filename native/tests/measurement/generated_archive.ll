target triple = "x86_64-w64-windows-gnu"
@shared = internal constant [4 x i32] [i32 3, i32 5, i32 11, i32 17], align 16
define dllexport i32 @archive_compute(i32 %value) {
entry:
  %index = and i32 %value, 3
  %address = getelementptr [4 x i32], ptr @shared, i32 0, i32 %index
  %item = load i32, ptr %address
  %result = add i32 %item, %value
  ret i32 %result
}
define dllexport i32 @archive_pointer(i32 %value) {
entry:
  %index = and i32 %value, 3
  %address = getelementptr [4 x i32], ptr @shared, i32 0, i32 %index
  %item = load i32, ptr %address
  %result = xor i32 %item, %value
  ret i32 %result
}
