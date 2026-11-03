declare i32 @bounded_wrapper_left(ptr, ptr, i32)
declare i32 @bounded_wrapper_right(ptr, ptr, i32)

define i32 @mixed_bounded_body(ptr %owned, ptr %measured, i32 %value) {
entry:
  %choose = icmp slt i32 %value, 0
  br i1 %choose, label %left, label %right
left:
  %l = call i32 @bounded_wrapper_left(ptr %owned, ptr %measured, i32 10)
  br label %join
right:
  %r = call i32 @bounded_wrapper_right(ptr %owned, ptr %measured, i32 20)
  br label %join
join:
  %result = phi i32 [ %l, %left ], [ %r, %right ]
  ret i32 %result
}
