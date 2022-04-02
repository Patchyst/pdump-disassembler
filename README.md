# pdump-disassember
Disassembler for 32/64 bit ELF binaries compiled on x86 and ARM architecture

## Dependencies
- libelf: ELF parser
- Capstone: disassembly framework
## Compilation and usage
Compile the source code using a C compiler such as gcc, making sure to link capstone and libelf.
```
gcc main.c -lcapstone -lelf -o pdump
```
pdump accepts two positional arguments, one required and one optional. The first is the filename of the binary to disassemble and the second, optional argument, is the name of the section to disassemble.
```
./pdump test_bin.out .plt
```
If no section argument is provided, then pdump will automatically disassemble the section referred to by .text
## A note on capstone engine version issues
Some versions of libcapstone fail to recognize the ```endbr64``` instruction which likely lead to the following error:
```
Failed to disassemble chunk of code (0)
```
To prevent this, build libcapstone directly from the offical [github repository](https://github.com/capstone-engine/capstone)

## Why use an ELF parser?
While an ELF binary can be parsed by reading the raw bytes of the file, finding the selected section/segment header, and using the offsets to aquire the desired data, this is often tedious for large projects. Thus, for the sake of readability and cross-compatibility, I chose to use a popular, open source ELF parsing library, libelf. Moreover, using libelf avoids the ridiculous number of calls to file IO functions, such as ```fseek()``` and ```fgets()```, required when parsing an ELF binary from scratch.
