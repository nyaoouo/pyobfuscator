declare i32 @mixed_original_negative(ptr, ptr, i32)
declare i32 @mixed_original_positive(ptr, ptr, i32)

define i32 @mixed_original_body(ptr %owned, ptr %measured, i32 %value) {
entry:
  %negative = icmp slt i32 %value, 0
  br i1 %negative, label %negative_edge, label %positive_edge
negative_edge:
  %result_negative = call i32 @mixed_original_negative(ptr %owned, ptr %measured, i32 14)
  ret i32 %result_negative
positive_edge:
  %result_positive = call i32 @mixed_original_positive(ptr %owned, ptr %measured, i32 10)
  ret i32 %result_positive
}
