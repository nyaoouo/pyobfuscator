declare i32 @bounded_wrapper_left(ptr, ptr, i32)

define i32 @mixed_bounded_body(ptr %owned, ptr %measured, i32 %value) {
entry:
  %choose = icmp slt i32 %value, 0
  br i1 %choose, label %left, label %join
left:
  %l = call i32 @bounded_wrapper_left(ptr %owned, ptr %measured, i32 10)
  br label %join
join:
  %result = phi i32 [ %l, %left ], [ 20, %entry ]
  ret i32 %result
}
