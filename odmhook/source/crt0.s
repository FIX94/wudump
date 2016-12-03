.section ".init"
.arm
.align 4

.globl _start

.extern odm_readkey
.type odm_readkey, %function

_start:
	#original code
	mov r5, r0
	#added function
	stmfd sp!, {r4-r11,lr}
	mov r0, r8
	mov r1, r10
	bl odm_readkey
	ldmfd sp!, {r4-r11,pc}
