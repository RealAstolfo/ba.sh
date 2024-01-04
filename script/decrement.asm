	%include "lib/sys/linux_elf.nasm"
	%include "syscalls.asm"

START:
	mov eax,SYS_EXIT ; Exit syscall
	mov rdi,1
	dec rdi
	syscall

END:
