.section .text$icf,"xr",one_only,twin_a
.globl twin_a
.def twin_a; .scl 2; .type 32; .endef
twin_a:
  leal 19(%rcx), %eax
  retq

.section .text$icf,"xr",one_only,twin_b
.globl twin_b
.def twin_b; .scl 2; .type 32; .endef
twin_b:
  leal 19(%rcx), %eax
  retq

.section .drectve,"yn"
.ascii " -export:twin_a -export:twin_b"
