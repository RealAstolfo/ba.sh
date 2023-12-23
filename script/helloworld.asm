%include "syscalls.asm"

START:
	mov rdi,SYS_WRITE
	mov rsi,TEXT
	mov rdx,ADDRESS_AFTER_TEXT-TEXT
	mov r15,10
.loop:
	mov rax,SYS_STDOUT
	syscall
	dec r15
	jnz .loop
	xor rdi,rdi
	call exit
TEXT:
	db 'hello world!'
ADDRESS_AFTER_TEXT:

END:	
