#Keebler 
A tiny Python class for unpacking object symbols from ELF binaries.

###Synopsis
Keebler is based on the [System V Application Binary Interface](http://sco.com/developers/gabi/latest/contents.html) draft spec. It supports 32 bit and 64 bit binaries.

###Features
Currently Keebler is able to unpack the following information:

1. Defined symbols from .symtab
2. Undefined symbols from .symtab
3. Section header names from .shtab

Included is a small sample script that will print these three pieces of information for an object file passed in as an argument. 


###TODO:
1. Implement a subset of the ABI name mangling spec so that Keebler can demangle symbol names unpacked from ELF binaries compiled by clang / LLVM and GCC.