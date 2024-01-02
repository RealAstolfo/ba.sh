	%include "lib/sys/linux_elf.nasm"
	%include "syscalls.asm"

START:

	mov eax,SYS_EXIT ; Exit syscall
	mov edi,1969
	syscall

END:
