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

declare -A asm_defines
function is_define() {
    str=$1
    str=`skip_space "$str"`
    if [[ $1 == "%define"* ]]; then
	asm_defines[$2]=$3
	return 0
    fi
    return 1
}

code_array=()

function read_assembly() {
    local line_array=()
    mapfile -t line_array < $1
    for line in "${line_array[@]}"; do
	file=`is_include $line`
	if [ $? -eq 0 ]; then
	    read_assembly $file
	    continue
	fi
	if is_define $line; then
	    continue
	fi
	# preprocess the defines found in the source.
	for key in "${!asm_defines[@]}"; do
	    value="${asm_defines[$key]}"
	    line="${line//$key/$value}"
	done

	if ! is_whitespace "$line"; then
	    code_array+=("$line")
	fi
    done
}

# load first file
read_assembly $1

###################################################################
# TOKEN TYPES
###################################################################
declare -A token_types

token_types["TOKEN_INVALID"]=-1 # placeholder value
token_types["TOKEN_BLOCK"]=-2   # used for storage management
token_types["TOKEN_FREE"]=-3    # free token marker, use to catch leaks

# Single-character operators.
token_types["TOKEN_WHITESPACE"]=' '
token_types["TOKEN_BOOL_NOT"]='!'
token_types["TOKEN_AND"]='&'
token_types["TOKEN_OR"]='|'
token_types["TOKEN_XOR"]='^'
token_types["TOKEN_NOT"]='~'
token_types["TOKEN_MULT"]='*'
token_types["TOKEN_DIV"]='/'
token_types["TOKEN_MOD"]='%'
token_types["TOKEN_LPAR"]='('
token_types["TOKEN_RPAR"]=')'
token_types["TOKEN_PLUS"]='+'
token_types["TOKEN_MINUS"]='-'
token_types["TOKEN_COMMA"]=','
token_types["TOKEN_LBRACE"]='{'
token_types["TOKEN_RBRACE"]='}'
token_types["TOKEN_LBRACKET"]='['
token_types["TOKEN_RBRACKET"]=-']'
token_types["TOKEN_QMARK"]='?'
token_types["TOKEN_EQ"]='=' # = or ==
token_types["TOKEN_GT"]='>'
token_types["TOKEN_LT"]='<'

# Multi-character operators.
token_types["TOKEN_SHL"]='<<' # << or <<<
token_types["TOKEN_SHR"]=-'>>'
token_types["TOKEN_SAR"]='>>>'
token_types["TOKEN_SDIV"]='//'
token_types["TOKEN_SMOD"]='%%'
token_types["TOKEN_GE"]='>='
token_types["TOKEN_LE"]='<='
token_types["TOKEN_NE"]='!=' # != or <>
token_types["TOKEN_LEG"]='<=>'
token_types["TOKEN_DBL_AND"]='&&'
token_types["TOKEN_DBL_OR"]='||'
token_types["TOKEN_DBL_XOR"]='^^'


token_types['TOKEN_NUM']='number' # numeric constant
token_types['TOKEN_ERRNUM']='badnumber' # malformed numeric constant
token_types['TOKEN_STR']='string' # string constant
token_types['TOKEN_ERRSTR']='badstring' # unterminated string constant
token_types['TOKEN_ID']='identity' # identifier
token_types['TOKEN_FLOAT']='float' # floating-point constant
token_types['TOKEN_HERE']='$' # $, not '$' because it is not an operator
token_types['TOKEN_BASE']='$$'


# Tokens for the assembler
token_types['TOKEN_SEG']='segment'
token_types['TOKEN_WRT']='wrt'
token_types['TOKEN_FLOATIZE']='__?floatX?__'
token_types['TOKEN_STRFUNC']='__utf16*__ __utf32*__'
token_types['TOKEN_IFUNC']='__ilog2*__'
token_types['TOKEN_DECORATOR']='decoration' # decorators such as {...}
token_types['TOKEN_OPMASK']='opmask' # translated token for opmask registers
token_types['TOKEN_SIZE']='bytesize' # BYTE WORD DWORD QWORD etc
token_types['TOKEN_SPECIAL']='special' # REL FAR NEAR STRICT NOSPLIT etc
token_types['TOKEN_PREFIX']='prefix' # A32 O16 LOCK REPNZ TIMES etc
token_types['TOKEN_REG']='register' # register name
token_types['TOKEN_INSN']=-'instruction' # instruction name

token_types['TOKEN_OTHER']='unimplemented' # % sequence without (current) meaning
token_types['TOKEN_PREPROC_ID']='%symbol' # Preprocessor ID eg. %symbol
token_types['TOKEN_MMACRO_PARAM']='macro' # MMacro paramater eg. $1
token_types['TOKEN_LOCAL_SYMBOL']='lsymbol' # Local symbol, eg. %%symbol
token_types['TOKEN_LOCAL_MACRO']=-'lmacro' # Local macro, eg %$symbol
token_types['TOKEN_ENVIRON']='%!'
token_types['TOKEN_INTERNAL_STR']='istring' # Unquoted string that should remain so
token_types['TOKEN_NAKED_STR']='nstring' # Unquoted string that should be requoted
token_types['TOKEN_PREPROC_Q']='%?'
token_types['TOKEN_PREPROC_QQ']=-'%??'
token_types['TOKEN_PREPROC_SQ']=-'%*?'
token_types['TOKEN_PREPROC_SQQ']='%*??'
token_types['TOKEN_PASTE']='%+'
token_types['TOKEN_COND_COMMA']='%,'
token_types["TOKEN_INDIRECT"]='%[...]'
token_types["TOKEN_XDEF_PARAM"]='%xdefine' # Used during %xdefine processing

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
    if [[ $1 =~ ^\.?[a-zA-Z_][a-zA-Z_0-9]*: ]]; then
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
