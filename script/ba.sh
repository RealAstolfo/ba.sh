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
    if [[ $1 == "%include"* ]]; then
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
    if [[ $1 == "%define" ]]; then
	return 0
    fi
    return 1
}

declare -A asm_macros
function is_macro() {
    if [[ $1 == "%macro"* ]]; then
	return 0
    fi
    return 1
}

function is_endmacro() {
    if [[ $1 == "%endmacro" ]]; then
	return 0
    fi
    return 1
}

# seems like shorthand to make nasm repeat the following X times each line.
function is_times() {
    if [[ $1 == "times" ]]; then
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

function remove_empty_lines() {
    local non_empty_lines=()
    for line in "${line_array[@]}"; do
	if [[ -n "$line" ]]; then
	    non_empty_lines+=("$line")
	fi
    done
    line_array=("${non_empty_lines[@]}")
}

function preprocess_assembly() {

    # remove all comments
    for index in "${!line_array[@]}"; do
	line_array[$index]="${line_array[$index]//;*/}" # remove comments denoted with ';'
	line_array[$index]=`skip_space "${line_array[$index]}"`
    done

    # find all assembly %include directives
    local check_again=true
    while [[ $check_again == true ]]; do
	check_again=false
	for index in "${!line_array[@]}"; do
	    if is_include ${line_array[$index]}; then
		IFS=' ' read _ file <<< ${line_array[$index]}
		local include_lines=()
		mapfile -t include_lines < "${file//\"/}" # remove the quotes
		# remove all comments... again.
		for index_j in "${!include_lines[@]}"; do
		    include_lines[$index_j]="${include_lines[$index_j]//;*/}" # remove comments denoted with ';'
		    include_lines[$index_j]=`skip_space "${include_lines[$index_j]}"`
		done
		local new_lines=("${line_array[@]:0:index}" "${include_lines[@]}" "${line_array[@]:index+1}")
		line_array=("${new_lines[@]}")
		check_again=true
		# because includes could contain includes, or there could be multiple includes in a file
		# we need to reset the loop
		break
	    fi
	done
    done

    remove_empty_lines
    
    # find all assembly %define directives
    for index in "${!line_array[@]}"; do
	if is_define ${line_array[$index]}; then
	    IFS=' ' read _ defname value <<< ${line_array[index]}
	    asm_defines[$defname]=$value
	    unset "line_array[$index]"
	fi
    done

    # preprocess the defines found in the source.
    local key_found=true
    while [[ $key_found == true ]]; do
	key_found=false  # Assume no more replacements will be made
	
	for key in "${!asm_defines[@]}"; do
            for index in "${!line_array[@]}"; do
		value="${asm_defines[$key]}"
		# Perform substitution and check if any replacement was made
		if [[ "${line_array[$index]}" =~ $key ]]; then
                    line_array[$index]="${line_array[$index]//$key/$value}"
                    key_found=true  # Set to true as a replacement was made
		fi
            done
	done
    done
    
    # find all assembly %macro and %endmacro directives
    local current_macro
    for index in "${!line_array[@]}"; do
	if is_macro ${line_array[$index]}; then
	    IFS=' ' read _ macname _ <<< ${line_array[$index]}
	    current_macro=$macname
	    unset "line_array[$index]"
	elif is_endmacro ${line_array[$index]}; then
	    unset current_macro
	    unset "line_array[$index]"
	elif [ -n "$current_macro" ]; then                                                                                            
            asm_macros["$current_macro"]+="${line_array[$index]}"
	    unset "line_array[$index]"
	else
	    continue
	fi
    done

    # remove empty lines so that "index" becomes zero again
    remove_empty_lines
    
    # find all 'times' macros and process them
    local new_lines=()
    local index_save
    for index in "${!line_array[@]}"; do
	if is_times ${line_array[$index]}; then
	    IFS=' ' read _ count wideness content <<< ${line_array[$index]}
	    unset "line_array[$index]"
	    index_save=$index
	    for ((i = 0; i < count; i++)); do
		new_lines+=("$wideness $content")
	    done
	    break
	fi
    done
    line_array=("${line_array[@]:0:index_save}" "${new_lines[@]}" "${line_array[@]:index_save+1}")
}

# load first file
preprocess_assembly $1

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

for line in "${line_array[@]}"; do
    echo "$line"
done

#main
