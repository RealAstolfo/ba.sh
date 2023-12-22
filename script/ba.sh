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
# OPS
###################################################################
function call() {
    if [[ "$1" == "exit" ]]; then
	exitprog
    fi
}


function exitprog() {
    exit $rdi
}

function syscall() {
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

function mov() {
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

function dec() {
    (($1--))
    local value=`read_register $1`
    if [ "$value" -eq 0 ]; then
	zf=1
    else
	zf=0
    fi
}

function xor() {
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

###################################################################
# REGISTERS
###################################################################
valid_registers=("rdi" "rsi" "rdx" "r15" "rax" "zf" "ip")

# zeroize the registers
for reg in ${valid_registers[@]}; do
    declare "${reg}=0"
done

###################################################################
# INSTRUCTIONS
###################################################################
registered_instructions=("mov" "syscall" "call" "dec" "jnz" "jmp" "xor")


for func in ${registered_instructions[@]}; do
    if [ "$(type -t "$func")" == "function" ]; then
	continue
    else
	echo "Function implementation of $func does not exist"
    fi
done

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

# See 
function isidstart() {
    case "$1" in
	[[:alpha:]] | '_' | '.' | '?' | '@' )
	    return 0 ;; # True
	*)
	    return 1 ;; # False
    esac
}

# See nasmlib.c#L708
#function stdscan() {
    #remove whitespace from front
#    str="$1"
#    str="${str#"${str%%[![:space:]]*}"}"
#    if [[ "$str" == $'\n' ]]; then
#	echo "0" # means t_type = 0
#    fi
    #L720
#    if isidstart "${str:0:1}" || [[ "${str:0:1}" == '$' && isidstart "${str:1:1}" ]]; then
#	local is_sym=false
#	if [ "${str:0:1}" == '$' ]; then
#	    is_sym=true
#	    str="${str:1}"
#	fi	
#   fi   
#}

function parse_line() {
    str="$1"
    str="${str#"${str%%[![:space:]]*}"}"
    echo $str
}

function load_code() {
    echo `parse_line "${code_array[$1]}"`
}

function is_register() {
    for reg in ${valid_registers[@]}; do
	if [ "$1" == "$reg" ]; then
	    return 0
	fi
    done
    return 1
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

function is_label() {
    if [[ $1 =~ ^[a-zA-Z_][a-zA-Z_0-9]*: ]]; then
	return 0
    else
	return 1
    fi
}

function execute() {
    IFS=' ' read -ra components <<< $1
    if is_label "${components[0]}"; then
	return 0
    fi
    
    for inst in ${registered_instructions[@]}; do
	if [ "${components[0]}" == "$inst" ]; then
	    $inst ${components[1]}
	    return 0
	fi
    done

    echo "Unknown operation ${components[0]}."
    return 1
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
	execute "$code"
	((ip++))
    done
}

main
