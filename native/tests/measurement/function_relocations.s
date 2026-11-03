.section .text$extent_reloc,"xr",one_only,extent_reloc
.globl extent_reloc
.def extent_reloc; .scl 2; .type 32; .endef
extent_reloc:
  movl $17, %eax
  retq
  .quad extent_fix_target-1
  .long extent_fix_target-3
  .rva extent_fix_target-2147483648
  # Unreachable fields used to exercise every COFF REL32 adjustment before linking.
  call extent_fix_target
  call extent_fix_target
  call extent_fix_target
  call extent_fix_target
  call extent_fix_target
  call extent_fix_target

.section .text$extent_fix_target,"xr",one_only,extent_fix_target
.globl extent_fix_target
.def extent_fix_target; .scl 2; .type 32; .endef
extent_fix_target:
  movl $19, %eax
  retq

.section .drectve,"yn"
.ascii " -export:extent_reloc"
