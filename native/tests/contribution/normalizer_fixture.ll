target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
target triple = "x86_64-w64-windows-gnu"

declare void @pyobf_native_contribution_site_v1(ptr, i32) nounwind
declare i32 @contribution_normalizer_identity(i32) nounwind

define i32 @contribution_compute(ptr %lease, i32 %value) nounwind {
entry:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 101)
  %pick = icmp slt i32 %value, 0
  br i1 %pick, label %duplicate.a, label %duplicate.b
duplicate.a:
  %a = add i32 %value, 7
  %b = xor i32 %a, 123
  %c = add i32 %b, 9
  br label %joined
duplicate.b:
  %d = add i32 %value, 7
  %e = xor i32 %d, 123
  %f = add i32 %e, 9
  br label %joined
joined:
  %merged = phi i32 [ %c, %duplicate.a ], [ %f, %duplicate.b ]
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 202)
  %early = icmp eq i32 %value, 2
  br i1 %early, label %literal, label %continued
literal:
  ret i32 41
continued:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 303)
  %g = mul i32 %merged, 3
  %ordinary = call i32 @contribution_normalizer_identity(i32 %g)
  %h = xor i32 %ordinary, 17
  %i = add i32 %h, 11
  ret i32 %i
}
