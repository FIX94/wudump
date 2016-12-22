.section ".init"
.arm
.align 4

.globl _start

.extern odm_readkey
.type odm_readkey, %function

_start:
	mov r1, r10
	mov r2, r8
	b odm_readkey
