#!/bin/bash

# Define the ELF header in hexadecimal
elf_header="7f454c4602010100000000000000000002003e0001000000"

# Convert the hexadecimal string to binary without xxd and sed
elf_header_bin=()
for ((i = 0; i < ${#elf_header}; i += 2)); do
  byte="\x${elf_header:$i:2}"
  elf_header_bin+=("$byte")
done

# Create a binary file with the specified ELF header
printf "%b" "${elf_header_bin[@]}" > minimal_elf_file

# Make the file executable (optional)
chmod +x minimal_elf_file

echo "Minimal ELF file 'minimal_elf_file' created."
