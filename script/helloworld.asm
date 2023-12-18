START:
	mov rdi,1
	mov rsi,TEXT
	mov rdx,ADDRESS_AFTER_TEXT-TEXT
	mov r15,10
.loop:
	mov rax,1
	syscall
	dec r15
	jnz .loop
	xor rdi,rdi
	call exit
TEXT:
	db 'hello world!'
ADDRESS_AFTER_TEXT:

END:	
