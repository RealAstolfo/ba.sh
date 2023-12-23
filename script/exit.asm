%include "syscalls.asm"

START:

	mov rax,SYS_EXIT # Exit syscall
	mov rdi,1969
	syscall

END:
