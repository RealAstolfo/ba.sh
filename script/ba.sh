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
    str="${str%"${str##*[![:space:]]}"}" # Remove trailing whitespace
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
    if [[ $1 =~ ^r[a-z0-9]+,[0-9]+$ ]]; then
	# detected mov register,immediate
        echo "opcode: 67"
    elif [[ $1 =~ ^r[a-z0-9]+,r[a-z0-9]+*$ ]]; then
	# detected niv register,register
        echo "opcode: 89"
    elif [[ $1 =~ ^r[a-z0-9]+,[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
	# detected mov register,memory
        echo "opcode: 8B"
    else
        echo "Unknown mov type: $1"
	exit 1
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

function encode_register() {
    local reg=$1
    case $reg in
	AL|AX|EAX|RAX|ST0|MMX0|XMM0|YMM0|ES|CR0|DR0)
	    printf "%X" "$((2#0000))" ;;
	CL|CX|ECX|RCX|ST1|MMX1|XMM1|YMM1|CS|CR1|DR1)
	    printf "%X" "$((2#0001))" ;;
	DL|DX|EDX|RDX|ST2|MMX2|XMM2|YMM2|SS|CR2|DR2)
	    printf "%X" "$((2#0010))" ;;
	BL|BX|EBX|RBX|ST3|MMX3|XMM3|YMM3|DS|CR3|DR3)
	    printf "%X" "$((2#0011))" ;;
	AH|SPL|SP|ESP|RSP|ST4|MMX4|XMM4|YMM4|FS|CR4|DR4)
	    printf "%X" "$((2#0100))" ;;
	CH|BPL|BP|EBP|RBP|ST5|MMX5|XMM5|YMM5|GS|CR5|DR5)
	    printf "%X" "$((2#0101))" ;;
	DH|SIL|SI|ESI|RSI|ST6|MMX6|XMM6|YMM6|CR6|DR6)
	    printf "%X" "$((2#0110))" ;;
	BH|DIL|DI|EDI|RDI|ST7|MMX7|XMM7|YMM7|CR7|DR6)
	    printf "%X" "$((2#0111))" ;;
	R8L|R8W|R8D|R8|MMX0|XMM8|YMM8|ES|CR8|DR8)
	    printf "%X" "$((2#1000))" ;;
	R9L|R9W|R9D|R9|MMX1|XMM9|YMM9|CS|CR9|DR9)
	    printf "%X" "$((2#1001))" ;;
	R10L|R10W|R10D|R10|MMX2|XMM10|YMM10|SS|CR10|DR10)
	    printf "%X" "$((2#1010))" ;;
	R11L|R11W|R11D|R11|MMX3|XMM11|YMM11|DS|CR11|DR11)
	    printf "%X" "$((2#1011))" ;;
	R12L|R12W|R12D|R12|MMX4|XMM12|YMM12|FS|CR12|DR12)
	    printf "%X" "$((2#1100))" ;;
	R13L|R13W|R13D|R13|MMX5|XMM13|YMM13|GS|CR13|DR13)
	    printf "%X" "$((2#1101))" ;;
	R14L|R14W|R14D|R14|MMX6|XMM14|YMM14|CR14|DR14)
	    printf "%X" "$((2#1110))" ;;
	R15L|R15W|R15D|R15|MMX7|XMM15|YMM15|CR15|DR15)
	    printf "%X" "$((2#1111))" ;;
    esac
}

function size_of_register() {
    local reg=$1
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
	case $operand in
	    AH|CH|BH|DH)
		return 1 ;; # no
	    *)
		continue ;; # skip
	esac
    done
    return 0 # yes
}


function encode_rex_prefix() {
    shift # shift parameters left
    local registers=("$@")

    local max_size=0
    local extended_register=false
    for register in "${registers[@]}"; do
	local size=size_of_register $register
	if [ $size -gt $max_size ]; then
	    max_size=$size
	fi

	case $register in
	    R[8-9]|R1[0-5]|XMM[8-9]|XMM1[0-5]|YMM[8-9]|YMM1[0-5]|CR[8-9]|CR1[0-5]|DR[8-9]|DR1[0-5]|SPL|BPL|SIL|DIL)
		extended_register=true ;;
	esac
    done
    
    # Initialize the REX prefix byte with fixed bits (0100)
    local rex_prefix="0100"

    # Set the W bit based on the operand size
    if [[ "$max_size" == "64" ]]; then
	rex_prefix+="1"
    else
	rex_prefix+="0"
    fi

    if [ $extended_register -eq true ]; then
	rex_prefix+="1"
    else
	rex_prefix+="0"
    fi
    

    # Set the X and B bits to 0
    # X Bit (Bit 1):
    # The X bit indicates whether an SSE, AVX, or AVX-512 register is used as an index in a memory addressing calculation.
    # If any of the registers in your list are SSE, AVX, or AVX-512 registers used as an index,
    # then you should set the X bit to 1; otherwise, it should be set to 0.

    # B Bit (Bit 2):
    # The B bit indicates whether the R8-R15, XMM8-XMM15, or YMM8-YMM15 registers
    # are used as the base in a memory addressing calculation.
    # If any of the registers in your list are R8-R15, XMM8-XMM15, or YMM8-YMM15 registers used as the base,
    # then you should set the B bit to 1; otherwise, it should be set to 0.

    # TODO: Implement this logic to support index/base addressing with extended registers
    rex_prefix+="00"

    printf "%02X" "$((16#$rex_prefix))"
}

# A REX prefix must be encoded when:
#
#    using 64-bit operand size and the instruction does not default to 64-bit operand size; or
#    using one of the extended registers (R8 to R15, XMM8 to XMM15, YMM8 to YMM15, CR8 to CR15 and DR8 to DR15); or
#    using one of the uniform byte registers SPL, BPL, SIL or DIL. 
#
# A REX prefix must not be encoded when:
#
#    using one of the high byte registers AH, CH, BH or DH. 
function generate_rex_prefix() {
    local register="$1"
    local rex_w=0  # Set to 1 for 64-bit operand size if needed

    # Check if the register requires REX.W (64-bit operand size)
    [[ $register =~ ^(r[8-9]|r1[0-5])$ ]] && rex_w=1

    # Construct REX prefix
    printf "0x%02X" $((0x40 | rex_w << 3))
}


generate_modrm() {
    destination="$1"
    source="$2"

    # Define register types
    general_registers=("rax" "rcx" "rdx" "rbx" "rsp" "rbp" "rsi" "rdi" "r8" "r9" "r10" "r11" "r12" "r13" "r14" "r15")
    xmm_registers=("xmm0" "xmm1" "xmm2" "xmm3" "xmm4" "xmm5" "xmm6" "xmm7")
    ymm_registers=("ymm0" "ymm1" "ymm2" "ymm3" "ymm4" "ymm5" "ymm6" "ymm7")

    # Function to get the register opcode and type
    get_register_info() {
        local operand="$1"
        local register_array=("${!2}")

        if [[ " ${register_array[*]} " =~ " $operand " ]]; then
            local reg_opcode=$((16#${operand: -1}))  # Extract the register number from the operand (e.g., rax -> 0, xmm3 -> 3)
            local reg_type="11"  # Register type
            echo "$reg_type$reg_opcode"
        else
            echo "Error: Unsupported register type for operand: $operand"
            return 1
        fi
    }

    # Function to get the mod and r/m fields for memory operand
    get_memory_info() {
        local operand="$1"
        local operand_size="$2"

        local mod="00"  # Memory addressing mode (default to direct addressing)
        local reg_type="00"  # Register type for r/m field

        if [[ "$operand" =~ ^\[.*\]$ ]]; then
            # Memory operand
            operand="${operand:1:${#operand}-2}"  # Remove square brackets
            local displacement=""
            local base=""
            local index=""
            local scale=""

            # Check for displacement
            if [[ "$operand" =~ ^[0-9]+$ ]]; then
                displacement="$operand"
            else
                IFS=',' read -ra parts <<< "$operand"
                local num_parts=${#parts[@]}

                case "$num_parts" in
                    1)
                        base="${parts[0]}"
                        ;;
                    2)
                        base="${parts[0]}"
                        index="${parts[1]}"
                        ;;
                    3)
                        displacement="${parts[0]}"
                        base="${parts[1]}"
                        index="${parts[2]}"
                        ;;
                esac
            fi

            # Determine register type and set mod field accordingly
            if [ -n "$base" ]; then
                reg_type=$(get_register_info "$base" "general_registers")
            elif [ -n "$index" ]; then
                reg_type=$(get_register_info "$index" "general_registers")
            fi

            # Set mod field based on displacement and register type
            if [ -n "$displacement" ]; then
                mod="01"  # Byte displacement
            elif [ "$reg_type" == "11000" ]; then
                mod="10"  # 64-bit addressing
            fi
        fi

        echo "$mod$reg_type"
    }

    # Determine mod, reg, and r/m fields based on operand types
    if [[ "$destination" =~ ^-?[0-9]+$ ]]; then
        # Immediate value as destination
        mod="11"
        reg_type="000"
        reg_opcode="000"
        rm="000"
    else
        # Register or memory destination
        reg_info=$(get_register_info "$destination" "general_registers")
        if [ $? -eq 1 ]; then
            return 1
        fi

        modrm_byte="${reg_info}"
        if [[ "$destination" =~ ^xmm[0-7]$ ]]; then
            # XMM register
            modrm_byte="${reg_info}10"
        elif [[ "$destination" =~ ^ymm[0-7]$ ]]; then
            # YMM register
            modrm_byte="${reg_info}10"
        elif [[ "$destination" =~ ^\[.*\]$ ]]; then
            # Memory operand
            memory_info=$(get_memory_info "$destination" "64")
            if [ $? -eq 1 ]; then
                return 1
            fi
            modrm_byte="${memory_info}"
        fi

        # Determine mod, reg, and r/m fields for the source operand
        if [[ "$source" =~ ^-?[0-9]+$ ]]; then
            # Immediate value as source
            mod="11"
            reg_type="000"
            reg_opcode="000"
            rm="000"
        else
            reg_info=$(get_register_info "$source" "general_registers")
            if [ $? -eq 1 ]; then
                return 1
            fi

            modrm_byte="${modrm_byte}${reg_info}"
            if [[ "$source" =~ ^xmm[0-7]$ ]]; then
                # XMM register
                modrm_byte="${modrm_byte}10"
            elif [[ "$source" =~ ^ymm[0-7]$ ]]; then
                # YMM register
                modrm_byte="${modrm_byte}10"
            elif [[ "$source" =~ ^\[.*\]$ ]]; then
                # Memory operand
                memory_info=$(get_memory_info "$source" "64")
                if [ $? -eq 1 ]; then
                    return 1
                fi
                modrm_byte="${modrm_byte}${memory_info}"
            fi
        fi
    fi

    # Combine mod, reg, and r/m fields to form ModRM byte
    modrm_byte="${mod}${modrm_byte}"

    echo "ModRM Byte: ${modrm_byte}"
}

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


# Test cases
test_instruction() {
  local instruction="$1"
  local expected_result="$2"

  needs_rex_prefix "$instruction"
  actual_result=$?

  if [ "$actual_result" -eq "$expected_result" ]; then
    echo "PASS: $instruction - Expected: $expected_result, Actual: $actual_result"
  else
    echo "FAIL: $instruction - Expected: $expected_result, Actual: $actual_result"
  fi
}
