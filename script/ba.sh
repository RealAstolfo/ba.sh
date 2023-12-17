#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "Error: File '$1' not found."
    exit 1
fi

line_array=()
mapfile -t line_array < $1

function is_whitespace() {
    local line="$1"
    [[ "$line" =~ ^[[:space:]]*$ ]]
}

code_array=()
for line in "${line_array[@]}"; do
    if ! is_whitespace "$line"; then
	code_array+=("$line")
    fi
done


###################################################################
# REGISTERS
###################################################################
rdi=0
rsi=0
rdx=0
r15=0
rax=0
# zero flag
zf=0
# instruction pointer
ip=0

###################################################################
# HELPER
###################################################################
function find_char() {
    for (( i=0; i<${#1}; i++ )); do
	if [[ "${1:$i:1}" == "$2" ]]; then
	    echo $i
	    return 0
	fi
    done
    return 1
}

function load_code() {
    echo "${code_array[$1]}"
}

is_register() {
    case $1 in
	"rdi" | "rsi" | "rdx" | "r15" | "rax" | "zf" | "ip")
	    return 0 # Success (true)
	    ;;
	*)
	    return 1 # Failure (false)
B	    ;;
    esac    
}

read_register() {
    if [[ -v $1 ]]; then
	eval ret="\$$1"
	echo $ret
	return 0
    fi

    echo "READ: Unknown register $1."
    exit 1
}

set_register() {
    if [[ -v $1 ]]; then
	eval "$1=\"$2\""
	return 0 # Success (true)
    fi

    echo "SET: Unknown register $1."
    exit 1
}


execute() {
    IFS=' ' read -ra components <<< $1
    case ${components[0]} in
	*"mov"*)
	    mov ${components[1]}
	    ;;
	*":"*)
	    ;;
	*"syscall"*)
	    syscall ${components[1]}
	    ;;
	*"call"*)
	    call ${components[1]}
	    ;;
	*"dec"*)
	    dec ${components[1]}
	    ;;
	*"jnz"*)
	    jnz ${components[1]}
	    ;;
	*"jmp"*)
	    jmp ${components[1]}
	    ;;
	*"xor"*)
	    xor ${components[1]}
	    ;;
	*)
	    echo "Error: Unknown operation ${components[0]}."
	    exit 1
    esac
    return 0
}

read_text() {
    local text_line=`find_label "$1:"`
    ((text_line++))
    local text=`load_code "$text_line"`
    # TODO: Implement parser (read char by char)
    IFS="'" read -ra components <<< $text
    echo ${components[1]}
    return 0
}

###################################################################
# OPS
###################################################################
call() {
    if [[ "$1" == "exit" ]]; then
	exitprog
    fi
}


exitprog() {
    exit $rdi
}

syscall() {
    case $rax in
	1) # Write Syscall
	    case $rdi in
		1)    
		    echo `read_text "$rsi"`
		    ;;
		*)
		    echo "Error: unsupported filedescriptor for write syscall"
		    exit 1
		    ;;
	    esac
	    ;;
	60) # Exit Syscall
	    exit $rdi
	    ;;
	*)
	    echo "Error: Unknown syscall $rax."
	    exit 1
	    ;;
    esac
    return 0
}

mov() {
    IFS=',' read -ra components <<< $1

    local register
    local value
    if is_register ${components[0]}; then
	register=${components[0]}
    else
	echo "Unknown register ${components[0]}"
	exit 1
    fi
    
    if is_register ${components[1]}; then
	value=`read_register "${components[1]}"`
    else
	value=${components[1]}
    fi

    set_register "$register" "$value"

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
	zf=0
	return 0
    fi
    
    
    if [ "$value" -eq 0 ]; then
	zf=1
    else
	zf=0
    fi
}

function jnz() {
    if [ $zf -eq 0 ]; then
	 jmp $1
    fi
}

function jmp() {
    ip=`find_label $1:`
}

dec() {
    (($1--))
    local value=`read_register $1`
    if [ "$value" -eq 0 ]; then
	zf=1
    else
	zf=0
    fi
}

xor() {
    IFS=',' read -ra components <<< $1

    local register
    local value
    local value_a
    local value_b
    if is_register ${components[0]}; then
	register=${components[0]}
	value_a=`read_register "${components[0]}"`
    else
	echo "Unknown register ${components[0]}"
	exit 1
    fi
    
    if is_register ${components[1]}; then
	value_b=`read_register "${components[1]}"`
    else
	value_b=${components[1]}
    fi
    value=$(((value_a & ~value_b) | (~value_a & value_b)))
    
    set_register "$register" "$value"
    if [ "$value" -eq 0 ]; then
	zf=1
    else
	zf=0
    fi
}

find_label() {
    local line_number=0
    for line in "${code_array[@]}"; do
	if [[ "$1" == "$line" ]]; then
	    echo $line_number
	    return 0
	fi
	((line_number++))
    done
    echo "Error: $1 not found."
    exit 1
}


main() {
    # you have to find the start first
    ip=`find_label "START:"`
    while true; do
	code=`load_code "$ip"`
	echo $code
	execute "$code"
	((ip++))
    done
}

main
