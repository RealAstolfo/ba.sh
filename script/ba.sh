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

function strip_space() {
    local -n str=$1
    str="${str#"${str%%[![:space:]]*}"}" # Skip whitespace
    str="${str%"${str##*[![:space:]]}"}" # Remove trailing whitespace
}

function is_include() {
    if [[ $1 == "%include" ]]; then
	return 0
    fi
    return 1
}

function is_db() {
    if [[ $1 == "db" ]]; then
	return 0
    fi
    return 1
}

function is_multi_db() {
    local data_type="$1"
    local input_string="$@"
    local entry_count=0
    local in_quotes=false

    case $data_type in
	db|dw|dd|dq)
	    ;;
	*)
	    return 1
	    ;;
    esac
    
    # Iterate over the input string and count the number of commas
    for ((i=0; i<${#input_string}; i++)); do
        char="${input_string:i:1}"

        if [[ $char == '"' ]]; then
            # Toggle the in_quotes flag when encountering a double quote
            if [[ $in_quotes == true ]]; then
                in_quotes=false
            else
		((entry_count++))
                in_quotes=true
            fi
        elif [[ $char == ',' ]]; then
	    if $in_quotes; then
		continue
	    else
		((entry_count++))
	    fi    
	fi
    done

    # Check if there are multiple entries
    if ((entry_count > 0)); then
        return 0 # Multiple entries found
    else
        return 1 # Only a single entry
    fi
}

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

declare -A asm_macro
function is_macro() {
    if [[ $1 == "%macro" ]]; then
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

function is_ifndef() {
    if [[ $1 == "%ifndef" ]]; then
	return 0
    fi
    return 1
}

function is_endif() {
    if [[ $1 == "%endif" ]]; then
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
    if [[ $1 == "org" ]]; then
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

function is_register() {
    local reg=${1^^} # ensures always capitalized
    case $reg in
	AL|AX|EAX|RAX|ST0|MMX0|XMM0|YMM0|ES|CR0|DR0|CL|CX|ECX|RCX|ST1|MMX1|XMM1|YMM1|CS|CR1|DR1|DL|DX|EDX|RDX|ST2|MMX2|XMM2|YMM2|SS|CR2|DR2|BL|BX|EBX|RBX|ST3|MMX3|XMM3|YMM3|DS|CR3|DR3|AH|SPL|SP|ESP|RSP|ST4|MMX4|XMM4|YMM4|FS|CR4|DR4|CH|BPL|BP|EBP|RBP|ST5|MMX5|XMM5|YMM5|GS|CR5|DR5|DH|SIL|SI|ESI|RSI|ST6|MMX6|XMM6|YMM6|CR6|DR6|BH|DIL|DI|EDI|RDI|ST7|MMX7|XMM7|YMM7|CR7|DR6|R8L|R8W|R8D|R8|MMX0|XMM8|YMM8|ES|CR8|DR8|R9L|R9W|R9D|R9|MMX1|XMM9|YMM9|CS|CR9|DR9|R10L|R10W|R10D|R10|MMX2|XMM10|YMM10|SS|CR10|DR10|R11L|R11W|R11D|R11|MMX3|XMM11|YMM11|DS|CR11|DR11|R12L|R12W|R12D|R12|MMX4|XMM12|YMM12|FS|CR12|DR12|R13L|R13W|R13D|R13|MMX5|XMM13|YMM13|GS|CR13|DR13|R14L|R14W|R14D|R14|MMX6|XMM14|YMM14|CR14|DR14|R15L|R15W|R15D|R15|MMX7|XMM15|YMM15|CR15|DR15)
	    return 0
    esac
    return 1
}

function is_memory() {
    local operand="$1"
    if [[ $operand =~ ^\[[^\]]+\]$ ]]; then
        return 0
    else
        return 1
    fi
}

function is_immediate() {
    local operand="$1"
    if [[ $operand =~ ^([+-]?[0-9]+|0x[a-fA-F0-9]+|[0-9a-fA-F]+h|0b[01]+)$ ]]; then
        return 0
    else
        return 1
    fi
}

function hex_to_binary() {
    local hex_number="$1"
    local binary_number=""

    # Loop through each character in the hex number
    for (( i=0; i<${#hex_number}; i++ )); do
        local digit=${hex_number:i:1}

        # Convert the hex digit to a 4-bit binary number
        case $digit in
            0) binary_number+="0000";;
            1) binary_number+="0001";;
            2) binary_number+="0010";;
            3) binary_number+="0011";;
            4) binary_number+="0100";;
            5) binary_number+="0101";;
            6) binary_number+="0110";;
            7) binary_number+="0111";;
            8) binary_number+="1000";;
            9) binary_number+="1001";;
            A|a) binary_number+="1010";;
            B|b) binary_number+="1011";;
            C|c) binary_number+="1100";;
            D|d) binary_number+="1101";;
            E|e) binary_number+="1110";;
            F|f) binary_number+="1111";;
        esac
    done

    echo $binary_number
}

function strip_comments() {
    local -n par="$1"
    local index=0
    for index in "${!par[@]}"; do
	par[index]="${par[index]//;*/}"
	strip_space par[index]
    done
}

function include() {
    local -n lines=$1
    local file=$2
    local index=$3
    
    local include_lines=()
    mapfile -t include_lines < "${file//\"/}"
    strip_comments include_lines
    lines=("${lines[@]:0:index}" "${include_lines[@]}" "${lines[@]:index+1}")
}

function define() {
    local defname=$1
    local index=$2
    local value="${@:3}"
    asm_defines[$defname]=$value
    unset line_array[$index]
}

function macro() {
    local -n lines=$1
    local current_macro
    for ((i = 0; i < ${#lines[@]}; i++)); do
	local tokens=(`get_tokens ${lines[$i]}`)
	if is_macro ${tokens[0]}; then
	    current_macro=${tokens[1]}
	    unset lines[$i]
	elif is_endmacro ${tokens[0]}; then
	    unset current_macro
	    unset lines[$i]
	elif [ -n "$current_macro" ]; then
	    asm_macros["$current_macro"]+="${lines[$i]}"
	    unset lines[$i]
	else
	    continue
	fi	
    done
}

function proc_times() {
    local -n lines=$1
    local new_lines=()
    local index_save
    for index in "${!lines[@]}"; do
	if is_times ${lines[$index]}; then
	    IFS=' ' read _ count wideness content <<< ${lines[$index]}
	    unset "lines[$index]"
	    index_save=$index
	    for ((i = 0; i < count; i++)); do
		new_lines+=("$wideness $content")
	    done
	    break
	fi
    done
    lines=("${lines[@]:0:index_save}" "${new_lines[@]}" "${lines[@]:index_save+1}")
}

function dbdddwdq() {
    local -n lines=$1
    local new_lines=()
    local check_again=true
    while [[ $check_again == true ]]; do
	check_again=false
	for index in "${!lines[@]}"; do
	    if is_multi_db ${lines[$index]}; then

		local line="${lines[$index]}"
		local entry_type="${line%% *}"
		line=${line#* }
		local within_quote=false
		local escaped=false
		local hex_values=()
		local resolved_lines=()
		local word
		
		for ((i = 0; i < ${#line}; i++)); do
		    local char="${line:i:1}"
		    case $char in
			\,)
			    # Test if word is hex
			    if [[ $word =~ ^0x[0-9A-Fa-f]+$ ]]; then
				hex_values+=("$word")
				word=
			    fi
			    ;;
			\\)
			    escaped=true
			    ;;
			\'|\")
			    if $escaped; then
				escaped=false
				hex_values+=("$(printf "0x%02X" "'$char")")
			    elif $within_quote; then
				within_quote=false
			    else
				within_quote=true
			    fi
			    ;;
			*)
			    if $within_quote; then
				hex_values+=("$(printf "0x%02X" "'$char")")
			    else
				word="$word$char"
			    fi
			    ;;
		    esac		    
		done
		for hex in "${hex_values[@]}"; do
		    resolved_lines+=("$entry_type $hex")
		done
		check_again=true
		local new_lines=("${lines[@]:0:$index}" "${resolved_lines[@]}" "${lines[@]:$index+1}")
		lines=("${new_lines[@]}")
	    fi
	done
    done
}

###################################################################
# HELPER
###################################################################

function encode_register() {
    local reg=${1^^} # ensures it is always captilized
    case $reg in
	AL|AX|EAX|RAX|ST0|MMX0|XMM0|YMM0|ES|CR0|DR0)
	    printf "%02X" "$((2#0000))" ;;
	CL|CX|ECX|RCX|ST1|MMX1|XMM1|YMM1|CS|CR1|DR1)
	    printf "%02X" "$((2#0001))" ;;
	DL|DX|EDX|RDX|ST2|MMX2|XMM2|YMM2|SS|CR2|DR2)
	    printf "%02X" "$((2#0010))" ;;
	BL|BX|EBX|RBX|ST3|MMX3|XMM3|YMM3|DS|CR3|DR3)
	    printf "%02X" "$((2#0011))" ;;
	AH|SPL|SP|ESP|RSP|ST4|MMX4|XMM4|YMM4|FS|CR4|DR4)
	    printf "%02X" "$((2#0100))" ;;
	CH|BPL|BP|EBP|RBP|ST5|MMX5|XMM5|YMM5|GS|CR5|DR5)
	    printf "%02X" "$((2#0101))" ;;
	DH|SIL|SI|ESI|RSI|ST6|MMX6|XMM6|YMM6|CR6|DR6)
	    printf "%02X" "$((2#0110))" ;;
	BH|DIL|DI|EDI|RDI|ST7|MMX7|XMM7|YMM7|CR7|DR6)
	    printf "%02X" "$((2#0111))" ;;
	R8L|R8W|R8D|R8|MMX0|XMM8|YMM8|ES|CR8|DR8)
	    printf "%02X" "$((2#1000))" ;;
	R9L|R9W|R9D|R9|MMX1|XMM9|YMM9|CS|CR9|DR9)
	    printf "%02X" "$((2#1001))" ;;
	R10L|R10W|R10D|R10|MMX2|XMM10|YMM10|SS|CR10|DR10)
	    printf "%02X" "$((2#1010))" ;;
	R11L|R11W|R11D|R11|MMX3|XMM11|YMM11|DS|CR11|DR11)
	    printf "%02X" "$((2#1011))" ;;
	R12L|R12W|R12D|R12|MMX4|XMM12|YMM12|FS|CR12|DR12)
	    printf "%02X" "$((2#1100))" ;;
	R13L|R13W|R13D|R13|MMX5|XMM13|YMM13|GS|CR13|DR13)
	    printf "%02X" "$((2#1101))" ;;
	R14L|R14W|R14D|R14|MMX6|XMM14|YMM14|CR14|DR14)
	    printf "%02X" "$((2#1110))" ;;
	R15L|R15W|R15D|R15|MMX7|XMM15|YMM15|CR15|DR15)
	    printf "%02X" "$((2#1111))" ;;
    esac
}

function size_of_register() {
    local reg=${1^^} # ensures its always capitalized
    case $reg in
	AL|CL|DL|BL|AH|SPL|CH|BPL|DH|SIL|BH|DIL|R8L|R9L|R10L|R11L|R12L|R13L|R14L|R15L)
	    printf "%d" "8" ;;
	AX|CX|DX|BX|SP|BP|SI|DI|R8W|R9W|R10W|R11W|R12W|R13W|R14W|R15W)
	    printf "%d" "16" ;;
	EAX|ECX|EDX|EBX|ESP|EBP|ESI|EDI|R8D|R9D|R10D|R11D|R12D|R13D|R14D|R15D)
	    printf "%d" "32" ;;
	RAX|RCX|RDX|RBX|RSP|RBP|RSI|RDI|R8|R9|R10|R11|R12|R13|R14|R15)
	    printf "%d" "64" ;;
	ST0|ST1|ST2|ST3|ST4|ST5|ST6|ST7)
	    printf "%d" "80" ;;
	MMX0|MMX1|MMX2|MMX3|MMX4|MMX5|MMX6|MMX7)
	    printf "%d" "64" ;;
	XMM0|XMM1|XMM2|XMM3|XMM4|XMM5|XMM6|XMM7|XMM8|XMM9|XMM10|XMM11|XMM12|XMM13|XMM14|XMM15)
	    printf "%d" "128" ;;
	YMM0|YMM1|YMM2|YMM3|YMM4|YMM5|YMM6|YMM7|YMM8|YMM9|YMM10|YMM11|YMM12|YMM13|YMM14|YMM15)
	    printf "%d" "256" ;;
	ES|CS|SS|DS|FS|GS)
	    printf "%d" "16" ;;
	CR0|CR1|CR2|CR3|CR4|CR5|CR6|CR7|CR8|CR9|CR10|CR11|CR12|CR13|CR14|CR15)
	    printf "%d" "32" ;;
	DR0|DR1|DR2|DR3|DR4|DR5|DR6|DR7|DR8|DR9|DR10|DR11|DR12|DR13|DR14|DR15)
	    printf "%d" "32" ;;
    esac
}

function encode_legacy_prefixes() {
    local instruction=$1
    local encoded_prefixes=""

    for (( i=0; i<${#instruction}; i++ )); do
        case ${instruction:i:4} in
            LOCK) encoded_prefixes+="F0" ;;
            REPNE|REPNZ) encoded_prefixes+="F2" ;;
            REP|REPE|REPZ) encoded_prefixes+="F3" ;;
        esac

        case ${instruction:i:2} in
            CS) encoded_prefixes+="2E" ;;
            SS) encoded_prefixes+="36" ;;
            DS) encoded_prefixes+="3E" ;;
            ES) encoded_prefixes+="26" ;;
            FS) encoded_prefixes+="64" ;;
            GS) encoded_prefixes+="65" ;;
        esac

        case ${instruction:i:2} in
            "66") encoded_prefixes+="66" ;;
            "67") encoded_prefixes+="67" ;;
        esac
    done

    echo "$encoded_prefixes"
}


# will always generate REX prefix unless using the high byte registers
# will make the machine code slightly larger but parsing simpler
# since according to https://wiki.osdev.org/X86-64_Instruction_Encoding#Usage, theres a lot of moments
# where having the prefix or not does not matter.
# this allows me to ignore instructions that default to 64bit operand size, which ignores this annoyingly complext 'if'
# "using 64-bit operand size and the instruction does not default to 64-bit operand size" 
function needs_rex_prefix() {
    local operands=("$@")
    for operand in "${operands[@]}"; do
	case ${operand^^} in
	    AH|CH|BH|DH)
		return 1 ;; # no
	esac
	case ${operand^^} in
	    R[8-9]|R1[0-5]|XMM[8-9]|XMM1[0-5]|YMM[8-9]|YMM[0-5]|CR[8-9]|CR[0-5]|DR[8-9]|DR[0-5])
		return 0 ;; # yes
	    SPL|BPL|SIL|DIL)
		return 0 ;; # yes
	    *)
		;;
	esac
	local size=`size_of_register $operand`
	if [ $size -eq 64 ]; then
	    return 0 # yes
	fi

	# TODO: Add checks for instructions that default to 64bit operand size
    done
    return 1 # no
}

function encode_rex_prefix() {
    local registers=("$@")
    
    local max_size=0
    local rex_r=false
    local rex_x=false  # New: For SIB index
    local rex_b=false  # New: For ModR/M or SIB base

    for register in "${registers[@]}"; do
        local size=`size_of_register $register`
        if [ $size > $max_size ]; then
            max_size=$size
        fi

        case $register in
            R[8-9]|R1[0-5])
                rex_r=true ;;
            # Add logic to set rex_x and rex_b based on the use of extended registers as index or base
            # Example: If your instruction format or addressing mode uses R8-R15 as index/base
            # set rex_x or rex_b to true accordingly
            # You will need to adjust this based on your specific instruction format and addressing
        esac
    done

    local rex_prefix="0100"  # Fixed bits

    # Set the W bit
    [ "$max_size" == 64 ] && rex_prefix+="1" || rex_prefix+="0"

    # Set the R bit
    [[ "$rex_r" == true ]] && rex_prefix+="1" || rex_prefix+="0"

    
    # Set the X and B bits based on addressing mode (to be implemented)
    [[ "$rex_x" == true ]] && rex_prefix+="1" || rex_prefix+="0"
    [[ "$rex_b" == true ]] && rex_prefix+="1" || rex_prefix+="0"
    printf "%02X" "$((2#$rex_prefix))"
}

###################################################################
# OPS
###################################################################

# Reminder to parse the following logic before it hits jmp,
# this way jmp can just determine the best opcode for the operand its given.
# destination - (source + sizeof(instruction))
# AKA, dst - end_of_jmp
function jmp() {
    local op1=$(( $1 ))
    bytes=()
    if [[ $op1 -ge -128 && $op1 -le 127 ]]; then
	# JMP rel8
	bytes+=("EB")
	# for some reason, despite specifying %02, it does FF's all the way to 8bytes
	local format=`printf "%02X" "$(( op1 & 0xFF ))"` 
	bytes+=("$format")
    else
	echo "ERROR: UNKNOWN INSTRUCTION: JMP $op1" >&2
	exit 1
    fi
    
    echo "${bytes[@]}"
}

function jnz() {
    local op1=$(( $1 ))
    bytes=()
    if [[ $op1 -ge -128 && $op1 -le 127 ]]; then
	# JNZ rel8
	bytes+=("75")
	# for some reason, despite specifying %02, it does FF's all the way to 8bytes
	local format=`printf "%02X" "$(( op1 & 0xFF ))"` 
	bytes+=("$format")
    else
	echo "ERROR: UNKNOWN INSTRUCTION: JNZ $op1" >&2
	exit 1
    fi
    echo "${bytes[@]}"
}

function call() {
    local op1=$(( $1 ))
    local rel
    bytes=()
    
#    if [[ $op1 -ge -32768 && $op1 -le 32767 ]]; then
#	# JMP rel8
#	bytes+=("E8")
#	# for some reason, despite specifying %02, it does FF's all the way to 8bytes
#	rel=`printf "%04X" "$(( op1 & 0xFFFF ))"` 
 #   else
    bytes+=("E8")
    rel=`printf "%08X" "$(( op1 & 0xFFFFFFFF ))"`
  #  fi
    
    
    local imm_len=${#rel}
    # rels need to be encoded backwards                                                                                      
    for ((i = imm_len - 2; i >= 0; i -= 2)); do
        local byte=${rel:i:2}
        bytes+=("$byte")
    done
    echo "${bytes[@]}"
}

function syscall() {
    local opcode=()
    opcode+=("0F")
    opcode+=("05")
    echo "${opcode[@]}"
}

# "The single-byte-opcode forms of the INC/DEC instructions are not available in 64-bit mode.
# INC/DEC functionality is still available using ModR/M forms of the same instructions (opcodes FF/0 and FF/1)." 
function dec() {
    local bytes=()
    local operand=$1
    if is_register $operand; then
	local prefix=''
	local size=`size_of_register $operand`
	if needs_rex_prefix $operand; then
	    prefix+='0100' # dec uses extension to the MODRM.rm field

	    if [[ $size -eq 64 ]]; then
		prefix+='1'
	    else
		prefix+='0'
	    fi

	    prefix+='0'
	    # SIB.index not needed here
	    prefix+='0'
	    case ${operand^^} in
		R[8-9]|R1[0-5]|XMM[8-9]|XMM1[0-5]|YMM[8-9]|YMM[0-5]|CR[8-9]|CR[0-5]|DR[8-9]|DR[0-5])
		    prefix+='1' ;;
		SPL|BPL|SIL|DIL)
		    prefix+='1' ;;
		*)
		    prefix+='0' ;;
	    esac
	    bytes+=("`printf "%02X" "$((2#$prefix))"`")
	fi
	
	if [[ $size -gt 8 ]]; then
	   bytes+=("FF")
	fi

	# DEC requires modrm byte
	local bits=''
	# DEC using only register
	bits+='11'
	# DEC uses modrm opcode extension 001
	bits+='001'
	local reg_code=`encode_register $operand`
	local reg_binary=`hex_to_binary $reg_code`
	bits+="${reg_binary:5}" # chop off 5 bits in front, since we wont need it here
	
	bytes+=("`printf "%02X" "$((2#$bits))"`")
    else
	echo "ERROR: UNKNOWN INSTRUCTION DEC $operand" >&2
	exit 1
    fi

    echo "${bytes[@]}"
}


function xor() {
    local operands=("$@")
    local bytes=()
    # register to register
    if is_register ${operands[0]} && is_register ${operands[1]}; then
	local prefix=''
	local size_op0=`size_of_register ${operands[0]}`
	local size_op1=`size_of_register ${operands[1]}`
	if [[ $size_op0 != $size_op1 ]]; then
	    echo "ERROR: REGISTER MISMATCH FOR ${operands[@]}" >&2
	    exit 1
	fi
	
	
	if needs_rex_prefix ${operands[@]}; then
	    prefix+='0100'

	    if [[ $size_op0 -eq 64 ]]; then
		prefix+='1'
	    else
		prefix+='0'
	    fi
	    # TODO: support addressing modes
	    prefix+='0'
	    # SIB.index not needed here
	    prefix+='0'
	    # MODRM.rm / SIB.base field not needed here
	    prefix+='0'
	    bytes+=("`printf "%02X" "$((2#$prefix))"`")
	fi

	if [[ $size_op0 -gt 8 ]]; then
	   bytes+=("31")
	fi

	# XOR requires modrm byte
	local bits=''
	# XOR using only register
	bits+='11'
	local reg_code=`encode_register ${operands[0]}`
	local reg_binary=`hex_to_binary $reg_code`
	bits+="${reg_binary:5}" # chop off 5 bits in front, since we wont need it here
	local reg_code=`encode_register ${operands[1]}`
	local reg_binary=`hex_to_binary $reg_code`
	bits+="${reg_binary:5}" # chop off 5 bits in front, since we wont need it here
	
	bytes+=("`printf "%02X" "$((2#$bits))"`")

    fi
    echo "${bytes[@]}"
}

function mov() {
    local operands=("$@")
    local opcode
    local bytes=()

    # attempt to resolve potential mathematical expression
    local result=$(echo "$(( ${operands[@]:1} ))" 2>/dev/null)
    if [ $? -eq 0 ]; then
	operands[1]=$result
    fi
    
    # if first operand is a register, and second operator is an immediate
    if is_register ${operands[0]} && [[ "${operands[1]}" =~ ^(0x|0X)?[0-9a-fA-F]+$ ]]; then
	local reg_size=`size_of_register ${operands[0]^^}`
	if needs_rex_prefix ${operands[0]}; then
	    prefix+='0100' # dec uses extension to the MODRM.rm field

	    if [[ $reg_size -eq 64 ]]; then
		prefix+='1'
	    else
		prefix+='0'
	    fi

	    prefix+='0'
	    # SIB.index not needed here
	    prefix+='0'
	    local extended=false
	    case ${operands[0]^^} in
		R[8-9]|R1[0-5]|XMM[8-9]|XMM1[0-5]|YMM[8-9]|YMM[0-5]|CR[8-9]|CR[0-5]|DR[8-9]|DR[0-5])
		    extended=true ;;
		SPL|BPL|SIL|DIL)
		    extended=true ;;
		*)
		    extended=false ;;
	    esac

	    if [[ $extended == true ]]; then
		prefix+='1'
	    else
		prefix+='0'
	    fi
	    
	    
	    bytes+=("`printf "%02X" "$((2#$prefix))"`")
	fi
	
	local regcode=`encode_register ${operands[0]^^}` # ^^ to make it all capital
	local immediate


	local reg_size=`size_of_register ${operands[0]^^}`
	case $reg_size in
	    8)
		opcode=(`printf "%02X" "$(( 0xB0 | 0x$regcode ))"`) ;;
	    16|32|64)
		opcode=(`printf "%02X" "$(( 0xB8 | 0x$regcode ))"`) ;;
	esac

	case $reg_size in
	    8)
		immediate=`printf "%02X" "$(( ${operands[1]} ))"` ;;
	    16)
		immediate=`printf "%04X" "$(( ${operands[1]} ))"` ;;
	    32)
		immediate=`printf "%08X" "$(( ${operands[1]} ))"` ;;
	    64)
		immediate=`printf "%016X" "$(( ${operands[1]} ))"` ;;
	esac
	
	bytes+=("$opcode")
	local imm_len=${#immediate}
	# immediates need to be encoded backwards
	for ((i = imm_len - 2; i >= 0; i -= 2)); do
	    local byte=${immediate:i:2}
	    bytes+=("$byte")
	done

    fi

    echo "${bytes[@]}"
#    if [[ $1 =~ ^r[a-z0-9]+,[0-9]+$ ]]; then
	# detected mov register,immediate
	
#        opcode+=""
#    elif [[ $1 =~ ^r[a-z0-9]+,r[a-z0-9]+*$ ]]; then
	# detected niv register,register
#        echo "opcode: 89"
#    elif [[ $1 =~ ^r[a-z0-9]+,[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
	# detected mov register,memory
#        echo "opcode: 8B"
#    else
#        echo "Unknown mov type: $1"
#	exit 1
#    fi
}

function encode_opcode() {
    local instruction=$1
    shift # shift parameters left, discarding the first
    echo `$instruction $@`
}

function encode_modrm() {
    local instruction=$1
    shift
    local operands="$@"
    local modrm=""

    # TODO: implement this
    # if any operand contains [register/memory + disp]
    # if disp is less than 128 MOD must == 01
    # else MOD must == 10
    # else if any operand contains [register/memory] MOD must == 00
    # else if all operands are register/memory MOD must == 11

    # REG == register_encode operand1
    # R/M == register_encode operand2
    
    local pattern='(^\s*(\[.*\])\s*$)|(^\s*([0-9]+)\s*$)|(^\s*(AL|CL|DL|BL|AH|S[PI]L|CH|B[PI]L|D[HI]L|R[8-9]?[LBWD]?|XMM[0-9]+|YMM[0-9]+|ES|CS|SS|DS|FS|GS|CR[0-9]+|DR[0-9]+)\s*$)'
    if [[ $operands =~ $pattern ]]; then
	if [[ ${BASH_REMATCH[2]} ]]; then
	    modrm+="10"
	elif [[ ${BASH_REMATCH[4]} ]]; then
	    modrm+="10"
	elif [[ ${BASH_REMATCH[6]} ]]; then
	    modrm+="00"
	fi
    fi

    echo "MOD field: $modfield"
}

# Takes label name as parameter, finds the org address. then increments the number based on how many bytes passed up until that label.
# returns the address
function calculate_label_address() {
    local label_name=$1
    local address
#    for line in "${line_array[@]}"; do
#    done
    
}

function parse_data() {
    local data_type="$1" # "db", "dw", etc
    shift
    local hex_values=()
    for entry in "$@"; do
	local regex="((0x[0-9A-Fa-f]+|\"[^\"]+\"),?)+"
	if [[ $entry =~ $regex ]]; then
	    local data="${BASH_REMATCH[0]}"
	    IFS=',' read -ra values <<< "$data"
	    for value in "${values[@]}"; do
		if [[ $value =~ ^0x[0-9A-Fa-f]+$ ]]; then
		    value="${value#0x}"
		    case $data_type in
			"db")
			    hex_values+=("${value}")
			    ;;
			"dw")
			    hex_values+=("${value:2:2}")
			    hex_values+=("${value:0:2}") 
			    ;;
			"dd")
			    hex_values+=("${value:6:2}")
			    hex_values+=("${value:4:2}")
			    hex_values+=("${value:2:2}")
			    hex_values+=("${value:0:2}")
			    ;;
			"dq")
			    hex_values+=("${value:14:2}")
			    hex_values+=("${value:12:2}")
			    hex_values+=("${value:10:2}")
			    hex_values+=("${value:8:2}")
			    hex_values+=("${value:6:2}")
			    hex_values+=("${value:4:2}")
			    hex_values+=("${value:2:2}")
			    hex_values+=("${value:0:2}")
			    ;;
		    esac
		elif [[ $value =~ ^\"([^\"]+)\"$ ]]; then
		    ascii_string="${BASH_REMATCH[1]}"
		    for ((i = 0; i < ${#ascii_string}; i++)); do
			hex_values+=("$(printf "%02X" "'${ascii_string:$i:1}")")
		    done
		fi
	    done
	fi
    done
    echo ${hex_values[@]}
}

function get_tokens() {
    local line="$@"
    local tokens=()

    local escaped=false
    local is_string=false
    
    # can be set to " ' or even `
    local current_string_marker=''

    
    # get tokens
    local token=''
    for ((i = 0; i < ${#line}; i++)); do
	local char="${line:i:1}"

	if $escaped; then
	   token+="$char"
	   escaped=false
	   continue
	fi
	
	case $char in
	   ' '|',')
		if $is_string; then
		   token+="$char"
		else
		   [[ -n $token ]] && tokens+=("$token")
		   token=''
		fi
		;;
	   \\)
		escaped=true
		;;
	   \'|\")
                if $is_string && [[ $current_string_marker == "$char" ]]; then
                    is_string=false
                    current_string_marker=''
                elif ! $is_string; then
                    is_string=true
                    current_string_marker="$char"
                else
                    token+="$char"
                fi
		;;
	   '-'|'+'|'*'|'/'|')'|'(')
	       # Ensures label math is tokenized
	       if $is_string; then
		   token+="$char"
	       else
		   [[ -n $token ]] && tokens+=("$token")
		   # Ensure the math operator is made itself a token.
		   tokens+=("$char")
		   token=''
	       fi
	       ;;
	   *)
	       token+="$char"
	       ;;
	esac
    done
    # grab the last one if it exists
    [[ -n $token ]] && tokens+=("$token")
    echo "${tokens[@]}"
}

function first_pass() {
    strip_comments line_array
    local len=${#line_array[@]}

    for ((i = 0; i < $len; i++)); do
	local tokens=(`get_tokens ${line_array[i]}`)
	if is_include ${tokens[0]}; then
	    include line_array "${tokens[1]}" $i
	    i=0
	    len=${#line_array[@]}
	fi
    done
    remove_empty_lines

    for ((i = 0; i < $len; i++)); do
	local tokens=(`get_tokens ${line_array[i]}`)
	if is_define ${tokens[0]}; then
	    define ${tokens[1]} $i "${tokens[@]:2}"
	fi
    done
    remove_empty_lines

    # replace all defines now
    for ((i = 0; i < $len; i++)); do
	local tokens=(`get_tokens ${line_array[i]}`)
	for token_index in "${!tokens[@]}"; do
	    if [ -v asm_defines["${tokens[token_index]}"] ]; then
		tokens[$token_index]=${asm_defines["${tokens[token_index]}"]}
		line_array[$i]="${tokens[@]}"
		i=0
	    fi
	done
    done
    
    macro line_array
    remove_empty_lines

    proc_times line_array
    remove_empty_lines

    dbdddwdq line_array
    remove_empty_lines
}

# function second_pass() {
# }

function main() {
    first_pass
    # second_pass


    local org_address
    local byte_count=0
    local -A labels


    # Temporary 0x0 addresses for all labels as we figure out the binary size
    for ((i = 0; i < ${#line_array[@]}; i++)); do
	local tokens=(`get_tokens ${line_array[i]}`)
	if is_label ${tokens[0]}; then
	    labels[${tokens[0]%?}]=0
	    continue
	fi
    done

    
    # Use temporary 0x0 label addresses to encode instructions. this way we get a better idea as to what the label addresses
    # should be. this will simulataniously replace the label address value
    for ((i = 0; i < ${#line_array[@]}; i++)); do
	local tokens=(`get_tokens ${line_array[i]}`)
	case "${tokens[0]}" in
	    BITS)
		continue ;;
	    org)
		org_address="${tokens[1]}" ;;
	    db)
		byte_count=$(( $byte_count + 0x1 )) ;;
	    dw)
		byte_count=$(( $byte_count + 0x2 )) ;;
	    dd)
		byte_count=$(( $byte_count + 0x4 )) ;;
	    dq)
		byte_count=$(( $byte_count + 0x8 )) ;;
	    *)
		if is_label "${tokens[0]}"; then
		    labels[${tokens[0]%?}]=$(( $org_address + $byte_count ))
		    continue
		fi

		# In some operands are labels, just replace it for the sake of getting the instruction size.
		for ((j = 1; j < ${#tokens[@]}; j++)); do
		    for label in "${!labels[@]}"; do
			local label_address="${labels[$label]}"
			# Temporarily process tokens as 0x0, this way we can get the byte length of the instructions
			tokens[j]=${tokens[j]//$label/0x0}
		    done
		done

		# resolve label math
		# for ((j = 1; j < ${#tokens[@]}; j++)); do
		#     local result
		#     case ${tokens[j]} in
		# 	'+'|'-'|'*'|'/')
		# 	    if [[ $j -gt 0 && $j -lt $((${#tokens[@]} - 1)) ]]; then
		# 		result=$(( ${tokens[j-1]} ${tokens[j]} ${tokens[j+1]} ))
		# 	    fi
		# 	    ;;
		#     esac
		#     if [[ -v result ]]; then
		# 	tokens[j-1]=$result
		# 	tokens=("${tokens[@]:0:j}" "${tokens[@]:j+2}")
		# 	((j--))
		#     fi
		# done

		# echo "Processing ${tokens[@]}..." >&2
		if [[ $(type -t "${tokens[0]}") == "function" ]]; then
		    bytes=(`${tokens[0]} ${tokens[@]:1}`)
		    byte_count=$(( $byte_count + ${#bytes[@]} ))
		#     echo "INSTRUCTION: ${tokens[0]} BYTES: ${bytes[@]}" >&2
		# else
		#     echo "INSTRUCTION ${tokens[0]} ${tokens[@]:1} not supported!" >&2
		fi
		;;
	esac
    done	

    local bytes=()

    # THIRD PASS, CONVERT TO BYTES!!!
    for ((i = 0; i < ${#line_array[@]}; i++)); do
	local tokens=(`get_tokens ${line_array[i]}`)
	if [[ "${tokens[0]}" == "BITS" ]]; then
	    continue # we do not currently support anything other than x64, so this is useless
	fi

	for token_index in "${!tokens[@]}"; do
	    if [ -v labels["${tokens[token_index]}"] ]; then
		tokens[$token_index]=${labels[${tokens[token_index]}]}
	    fi
	done

	case "${tokens[0]}" in
	    db)	
		local result=`printf "0x%02X" "$((${tokens[@]:1}))"`
		if [[ -v result ]]; then
		    tokens=("${tokens[0]}" "$result")
		fi
		;;
	    dw)
		local result=`printf "0x%04X" "$((${tokens[@]:1}))"`
		if [[ -v result ]]; then
		    tokens=("${tokens[0]}" "$result")
		fi
		;;
	    dd)
		local result=`printf "0x%08X" "$((${tokens[@]:1}))"`
	       	if [[ -v result ]]; then
		    tokens=("${tokens[0]}" "$result")
		fi
		;;
	    dq)
		local result=`printf "0x%016X" "$((${tokens[@]:1}))"`
		if [[ -v result ]]; then
		    tokens=("${tokens[0]}" "$result")
		fi
		;;
	esac

	
	case "${tokens[0]}" in
            db|dw|dd|dq)
		local data=(`parse_data "${tokens[0]}" "${tokens[@]:1}"`)
		for byte in "${data[@]}"; do
		    bytes+=("$byte")
		done
		continue
		;;
	esac

	local inst=()
	if [[ "${tokens[0]}" == "mov" ]]; then
	    # THIS IS EXTREMELY SENSITIVE, it will only work right if the first parameter is a register
	    inst=(`mov ${tokens[1]} $(( ${tokens[@]:2} ))`)
	elif [[ "${tokens[0]}" == "syscall" ]]; then
	    inst=(`syscall`)
	elif [[ "${tokens[0]}" == "jmp" ]]; then
	    # HACK: TODO: Rework parser to know all the bytes needed way ahead of time
 	    # TODO: make extra parsing to check the smallest the instruction can be?
	    inst=(`jmp 0`) # TODO: Figure out how to handle literally anything bigger than 8bits
	    local rel=$(( ${tokens[1]} - (org_address + ${#bytes[@]} + ${#inst[@]}) ))
	    inst=(`jmp $rel`) # TODO: Figure out how to handle literally anything bigger than 8bits
	elif  [[ "${tokens[0]}" == "jnz" ]]; then
	    # HACK: TODO: Rework parser to know all the bytes needed way ahead of time
 	    # TODO: make extra parsing to check the smallest the instruction can be?
	    inst=(`jnz 0`) # TODO: Figure out how to handle literally anything bigger than 8bits
	    local rel=$(( ${tokens[1]} - (org_address + ${#bytes[@]} + ${#inst[@]}) ))
	    inst=(`jnz $rel`) # TODO: Figure out how to handle literally anything bigger than 8bits
	elif [[ "${tokens[0]}" == "call" ]]; then
	    # HACK: TODO: Rework parser to know all the bytes needed way ahead of time
 	    # TODO: make extra parsing to check the smallest the instruction can be?
	    inst=(`call 0`) # TODO: Figure out how to handle literally anything bigger than 8bits
	    local rel=$(( ${tokens[1]} - (org_address + ${#bytes[@]} + ${#inst[@]}) ))
	    inst=(`call $rel`) # TODO: Figure out how to handle literally anything bigger than 8bits
	elif [[ "${tokens[0]}" == "dec" ]]; then
	    inst=(`dec ${tokens[1]}`)
	elif [[ "${tokens[0]}" == "xor" ]]; then
	    inst=(`xor ${tokens[@]:1}`)
	fi

	echo "INSTRUCTION: ${tokens[0]} BYTES: ${inst[@]}" >&2
	for ((j = 0; j < ${#inst[@]}; j++)); do
	    bytes+=("${inst[$j]}")
	done	    
    done
    
    byte_string=""
    for byte in "${bytes[@]}"; do
	byte_string="${byte_string}${byte}"
    done
    byte_string="${byte_string// /}"

    final_bytes=()
    for ((i = 0; i < ${#byte_string}; i += 2)); do
	byte="\x${byte_string:$i:2}"
	final_bytes+=("$byte")
    done


    printf "%b" "${final_bytes[@]}" > a.out
    chmod +x a.out
}

#first_pass
main
for line in "${line_array[@]}"; do
   echo "$line"
done

#main
#for line in "${line_array[@]}"; do
#    echo "$line"
#done

