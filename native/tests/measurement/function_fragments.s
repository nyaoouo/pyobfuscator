.section .text$extent_split,"xr",one_only,extent_split
.globl extent_split
.def extent_split; .scl 2; .type 32; .endef
extent_split:
  jmp extent_cold

.section .text$extent_cold,"xr",associative,extent_split
.def extent_cold; .scl 3; .type 32; .endef
extent_cold:
  leal 7(%rcx), %eax
  retq
  .quad extent_split
  .rva extent_split

.globl extent_alias
.def extent_alias; .scl 2; .type 32; .endef
.set extent_alias, extent_split
