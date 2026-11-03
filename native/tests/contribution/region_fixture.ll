target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-w64-windows-gnu"

declare void @pyobf_native_contribution_site_v1(ptr, i32) nounwind
declare i32 @contribution_region_choice(ptr, i32) nounwind
declare void @contribution_region_step(ptr, i32, i32) nounwind
declare void @contribution_region_after(ptr) nounwind
declare void @contribution_region_anchor(ptr) nounwind noduplicate
declare void @contribution_region_entered(ptr) nounwind
declare void @contribution_region_tick(ptr) nounwind
declare void @contribution_region_positive(ptr) nounwind
declare void @contribution_region_negative(ptr) nounwind

define i32 @contribution_region(ptr %lease, i32 %value, ptr %io, i32 %rounds) noinline {
pre:
  %counter = getelementptr i32, ptr %io, i32 0
  %result = getelementptr i32, ptr %io, i32 1
  %remaining = getelementptr i32, ptr %io, i32 2
  %before = getelementptr i32, ptr %io, i32 3
  store volatile i32 %rounds, ptr %remaining
  store volatile i32 0, ptr %result
  br label %prefix
prefix:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 899) nounwind
  %old.before = load volatile i32, ptr %before
  %next.before = add i32 %old.before, 1
  store volatile i32 %next.before, ptr %before
  %parity = and i32 %value, 1
  %odd = icmp ne i32 %parity, 0
  br i1 %odd, label %prefix.a, label %prefix.b
prefix.a:
  store volatile i32 3, ptr %counter
  call void @contribution_region_entered(ptr %io) nounwind
  br label %region.start
prefix.b:
  store volatile i32 2, ptr %counter
  call void @contribution_region_entered(ptr %io) nounwind
  br label %region.start
region.start:
  call void @contribution_region_anchor(ptr %io) nounwind noduplicate
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 801) nounwind
  %count = load volatile i32, ptr %counter
  %more = icmp sgt i32 %count, 0
  br i1 %more, label %region.body, label %region.out
region.body:
  %choice = call i32 @contribution_region_choice(ptr %io, i32 %value) nounwind
  %positive = icmp ne i32 %choice, 0
  br i1 %positive, label %region.yes, label %region.no
region.yes:
  call void @contribution_region_step(ptr %io, i32 %value, i32 7) nounwind
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 802) nounwind
  call void @contribution_region_positive(ptr %io) nounwind
  br label %region.tail
region.no:
  call void @contribution_region_step(ptr %io, i32 %value, i32 -5) nounwind
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 803) nounwind
  call void @contribution_region_negative(ptr %io) nounwind
  br label %region.tail
region.tail:
  %old.count = load volatile i32, ptr %counter
  %next.count = sub i32 %old.count, 1
  store volatile i32 %next.count, ptr %counter
  call void @contribution_region_tick(ptr %io) nounwind
  br label %region.start
region.out:
  call void @pyobf_native_contribution_site_v1(ptr %lease, i32 898) nounwind
  call void @contribution_region_after(ptr %io) nounwind
  %old.remaining = load volatile i32, ptr %remaining
  %next.remaining = sub i32 %old.remaining, 1
  store volatile i32 %next.remaining, ptr %remaining
  %repeat = icmp sgt i32 %next.remaining, 0
  br i1 %repeat, label %prefix, label %done
done:
  %answer = load volatile i32, ptr %result
  ret i32 %answer
}
