%include "lib/sys/linux_elf.nasm"
%include "lib/sys/syscalls.nasm"
	
START:

	mov rax,SYS_EXIT
	mov rdi,1969
	syscall

END: