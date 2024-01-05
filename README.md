TLDR:
an assembler targeting NASM syntax

preprocessors supported:
%include
%macro, %endmacro
%define

instructions supported
MOV r16/r32/r64,imm16/imm32/imm64
syscall
dec r32/r64
jnz rel8
jmp rel8
call rel32/rel64
xor r32/r64

data types supported
db (has string parsing)
dw
dd
dq
