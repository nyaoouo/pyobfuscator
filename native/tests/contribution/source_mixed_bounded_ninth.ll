declare i32 @bounded_compute_negative(ptr, ptr, i32)
declare i32 @bounded_compute_zero(ptr, ptr, i32)
declare i32 @bounded_compute_positive(ptr, ptr, i32)

define i32 @mixed_bounded_body(ptr %owned, ptr %measured, i32 %value) {
entry:
  %negative = icmp slt i32 %value, 0
  br i1 %negative, label %negative_edge, label %nonnegative
negative_edge:
  %n = call i32 @bounded_compute_negative(ptr %owned, ptr %measured, i32 11)
  br label %join
nonnegative:
  %zero = icmp eq i32 %value, 0
  br i1 %zero, label %zero_edge, label %positive_edge
zero_edge:
  %z = call i32 @bounded_compute_zero(ptr %owned, ptr %measured, i32 17)
  br label %join
positive_edge:
  %p = call i32 @bounded_compute_positive(ptr %owned, ptr %measured, i32 23)
  %extra = icmp eq i32 %value, 42
  br i1 %extra, label %join, label %extra_edge
extra_edge:
  br label %join
join:
  %result = phi i32 [ %n, %negative_edge ], [ %z, %zero_edge ],
                    [ %p, %positive_edge ], [ %p, %extra_edge ]
  ret i32 %result
}
