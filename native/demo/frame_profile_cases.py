"""Call-count and target-profile inputs for ordinary and hybrid framed owners."""

from hybrid_eh_cases import SOURCE as PHI_SOURCE, HARNESS as PHI_HARNESS


SOURCE = PHI_SOURCE.replace("to label %join unwind label %pad", "to label %join unwind label %pad, !prof !0", 1)
SOURCE = SOURCE.replace("%two = invoke i32 @throw_or_return(i32 %x) to label %join unwind label %pad",
                        "%two = invoke i32 @throw_or_return(i32 %x) to label %join unwind label %pad, !prof !1")
SOURCE += '''
define i32 @normal_profile(i1 zeroext %left, i32 %x) {
entry:
  br i1 %left, label %a, label %b
a:
  %one = call i32 @throw_or_return(i32 %x), !prof !2
  ret i32 %one
b:
  %shifted = add i32 %x, 2
  %two = call i32 @throw_or_return(i32 %shifted), !prof !1
  ret i32 %two
}
!0 = !{!"branch_weights", !"expected", i32 999, i32 1}
!1 = !{!"VP", i32 0, i64 100, i64 123456, i64 99}
!2 = !{!"branch_weights", !"expected", i32 99}
'''

INTERNAL_TARGET = '''
define internal i32 @profile_target(i32 %x) noinline {
entry:
  %value = call i32 @throw_or_return(i32 %x)
  ret i32 %value
}
'''

HARNESS = PHI_HARNESS.replace("int hybrid_phi(bool, int);", "int hybrid_phi(bool, int); int normal_profile(bool, int);")
HARNESS = HARNESS.replace('std::printf("%d:%d:%d:%d\\n",flag,x,value,cleanup_count);',
    'int extra; try {extra=normal_profile(flag!=0,x);}catch(int error){extra=200+error;}\n'
    'std::printf("%d:%d:%d:%d:%d\\n",flag,x,value,cleanup_count,extra);')
