target datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"
target triple = "x86_64-w64-windows-gnu"

declare i32 @__gxx_personality_seh0(...)
declare void @pyobf_native_contribution_site_v1(ptr, i32) nounwind
declare i32 @contribution_may_throw(i32)
declare void @contribution_cleanup(i32) nounwind

define i32 @contribution_hybrid_literal(ptr %lease, i32 %value) personality ptr @__gxx_personality_seh0 {
entry:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 701) #0
  %pick = icmp eq i32 %value, 5
  br i1 %pick, label %left, label %right
left:
  %a = invoke i32 @contribution_may_throw(i32 %value) to label %returned.a unwind label %pad
right:
  %b = invoke i32 @contribution_may_throw(i32 %value) to label %returned.b unwind label %pad
returned.a:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 702) #0
  call void @contribution_cleanup(i32 %value)
  ret i32 41
returned.b:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 703) #0
  call void @contribution_cleanup(i32 %value)
  ret i32 41
pad:
  %exception = landingpad {ptr, i32} cleanup
  call void @contribution_cleanup(i32 %value)
  resume {ptr, i32} %exception
}

attributes #0 = { nomerge }
