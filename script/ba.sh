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

function skip_space() {
    str=$1
    str="${str#"${str%%[![:space:]]*}"}" # Skip whitespace
    echo $str
}

function is_include() {
    str=$1
    str=`skip_space "$str"`
    if [[ $1 == "%include"* ]]; then
	echo "${2//\"/}" # strip quote literals
	return 0
    fi
    return 1
}

declare -A asm_labels
function is_label() {
    if [[ $1 =~ ^\.?[a-zA-Z_][a-zA-Z_0-9]*: ]]; then
	return 0
    else
	return 1
    fi
}

declare -A asm_defines
function is_define() {
    str=$1
    str=`skip_space "$str"`
    if [[ $str == "%define"* ]]; then
	asm_defines[$2]=$3
	return 0
    fi
    return 1
}

declare -A asm_macros
function is_macro() {
    str=$1
    str=`skip_space "$str"`
    if [[ $str == "%macro"* ]]; then
	current_macro=$2
	return 0 # reading macro
    elif [[ $str == "%endmacro" ]]; then
	unset current_macro
	return 0 # reading macro
    elif [ -n "$current_macro" ]; then
	asm_macros["$current_macro"]+=" $@"
	return 0 # reading macro
    else
	return 1 # not reading macro
    fi
}

# seems like shorthand to make nasm repeat the following X times each line.
function is_times() {
    str=$1
    str=`skip_space "$str"`
    if [[ $str == "times"* ]]; then
	return 0
    fi
    return 1
}

function is_org() {
    str=$1
    str=`skip_space "$str"`
    if [[ $str == "org"* ]]; then
	return 0
    fi
    return 1
}

declare org_address
code_array=()
function read_assembly() {
    local line_array=()
    mapfile -t line_array < $1
    for line in "${line_array[@]}"; do
	# preprocess remove comments
	line="${line//;*/}"
	# remove unnecessary whitespace in front
	line=`skip_space "$line"`
	# record org address
	if is_org $line; then
	    IFS=' ' read _ addr <<< $line
	    org_address=$addr
	    continue
	fi
	
	# preprocess includes
	file=`is_include $line`
	if [ $? -eq 0 ]; then
	    read_assembly $file
	    continue
	fi

	if is_define $line; then
	    continue # records the define into an associative array,
	             # and continues to ensure it wont end up in code_array
	fi

	if is_macro $line; then
	    continue
	fi

	if is_label $line; then
	    asm_labels["$line"]="0x2000000" # TODO: load org address and increment labels
	fi

	# preprocess the defines found in the source.
	for key in "${!asm_defines[@]}"; do
	    value="${asm_defines[$key]}"
	    line="${line//$key/$value}"
	done

	if is_times $line; then
	    IFS=' ' read _ count wideness content <<< $line
	    for ((i = 0; i < count; i++)); do
		code_array+=("$wideness $content")
	    done
	    continue
	fi

	# if there is anything left in the line, append it to the array
	if ! is_whitespace "$line"; then
	    code_array+=("$line")
	fi
    done
}

# load first file
read_assembly $1

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
	set_bit flag_register ${flag_bit["zf"]} 0  
	return 0
    fi
    
    
    if [ "$value" -eq 0 ]; then
	set_bit flag_register ${flag_bit["zf"]} 1
    else
	set_bit flag_register ${flag_bit["zf"]} 0
    fi
}

function jnz() {
    local zf=`get_bit flag_register ${flag_bit["zf"]}`
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
	set_bit flag_register ${flag_bit["zf"]} 1
    else
	set_bit flag_register ${flag_bit["zf"]} 0
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
	set_bit flag_register ${flag_bit["zf"]} 1
    else
	set_bit flag_register ${flag_bit["zf"]} 0
    fi
}

###################################################################
# FLAGS Ref: https://en.wikipedia.org/wiki/FLAGS_register
###################################################################
flag_register=0
declare -A flag_bit
flag_bit["zf"]=6

###################################################################
# REGISTERS
###################################################################
declare -A register_wideness
register_wideness["rdi"]=64
register_wideness["rsi"]=64
register_wideness["rdx"]=64
register_wideness["r15"]=64
register_wideness["rax"]=64
register_wideness["ip"]=64

valid_registers=("rdi" "rsi" "rdx" "r15" "rax" "ip")

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
function evaluate_expr() {
    local expr="$1"
    echo "$((expr))"
}

function hex_to_binary() {
    local hex="$1"
    local binary=""
    for ((i = 0; i  < ${#hex}; i += 2)); do
	binary+="\x${hex:$i:2}"
    done
    printf "%b" "$binary"
}

function parse_db() {
    local line="$1"
    hex_expr="${line#*0x}"
    hex_value="${hex_expr%%[ ,+-/*]*}"
    if [[ "$hex_expr" == *'+'* || "$hex_expr" == *'-'* || "$hex_expr" == *'*'* || "$hex_expr" == *'/'* ]]; then
	eval_result=$(evaluate_expr "$hex_expr")
	echo "$(hex_to_binary "$eval_result")"
    else
	echo "$(hex_to_binary "$hex_value")"
    fi
}

function get_bit() {
    if (($2 < 0 || $2 >= 64)); then
	echo "bit selection is outside valid range"
	exit 1
    fi
    local bit=$(( ($1 >> $2) & 1 ))
    echo $bit
    return 0
}

function set_bit() {
    if (($2 < 0 || $2 >= 64)); then
	echo "bit selection is outside valid range"
	exit 1
    fi
    local num=$1

    num=$((num & ~(1 << $2)))
    num=$((num | ($3 << $2)))
    eval "$1=$num"
    return 0
}


function parse_line() {
    str="$1"
    str=`skip_space "$str"`
    if [[ $str == '\n' ]]; then
	return 0
    fi
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

function read_register() {
    if [[ -v $1 ]]; then
	eval ret="\$$1"
	echo $ret
	return 0
    fi

    echo "READ: Unknown register $1."
    exit 1
}

function set_register() {
    if [[ -v $1 ]]; then
	eval "$1=\"$2\""
	return 0 # Success (true)
    fi

    echo "SET: Unknown register $1."
    exit 1
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

function read_text() {
    local text_line=`find_label "$1:"`
    ((text_line++))
    local text=`load_code "$text_line"`
    # TODO: Implement parser (read char by char)
    IFS="'" read -ra components <<< $text
    echo ${components[1]}
    return 0
}


function find_label() {
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

for line in "${code_array[@]}"; do
    echo "$line"
done

main
