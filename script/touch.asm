	%include "lib/sys/linux_elf.nasm"
	%include "syscalls.asm"		
START:
				; don't bother checking argc
	
				; open the input file	
	mov rdi,[SYS_ARGC_START_POINTER+16] ; command line arg
	mov esi,SYS_CREATE_FILE	; put READ_ONLY flags in {rsi}
	mov edx,SYS_DEFAULT_PERMISSIONS	; default R/W flags in {rdx}
	mov al,SYS_OPEN	
	syscall			; syscall to open file
				; {rax} contains new file descriptor
	
				; don't need to close the file

	mov al,SYS_EXIT		; who cares about a retval?
	syscall
	
END:	
