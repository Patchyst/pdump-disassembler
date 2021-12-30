# pdump-disassember
Disassembler for 32/64 bit ELF binaries compiled on x86 and ARM architecture

## Dependencies
- libelf: ELF parser
- Capstone: disassembly framework
## Compilation and usage
Compile the source code using a C compiler such as gcc, making sure to link capstone and libelf.
```gcc main.c -lcapstone -lelf -o pdump```
pdump accepts two positional arguments, one required and one optional. The first is the filename of the binary to disassemble and the second, optional argument, is the name of the section to disassemble.
```./pdump test_bin.out .plt```
If no section argument is provided then pdump will automatically disassemble the section referred to by .text
