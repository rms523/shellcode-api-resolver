# Windows Shellcode Examples
> Educational shellcode examples focusing on Windows API resolution techniques

## Overview
This repository contains examples demonstrating how to manually resolve Windows APIs by parsing the Process Environment Block (PEB). The code is written for educational purposes and shows common techniques used in position-independent code.

## Contents
- `src/main.c` - C wrapper to demonstrate the functionality
- `src/shellcode.asm` - Assembly code implementing PEB parsing and API resolution

## Building
### Prerequisites
- NASM assembler
- Visual Studio or MinGW
- Windows SDK

### Build Instructions
```cmd
nasm -f win32 shellcode.asm -o shellcode.o
mingw32-gcc -m32 main.c shellcode.o -o runme.exe
```

## Technical Details
The code demonstrates:
- PEB traversal techniques
- Module list enumeration
- PE header parsing
- Export directory resolution

## Security Notice
This code is for educational purposes only. Understanding these techniques is valuable for:
- Malware analysis
- Exploit development
- Security research

However, these techniques are commonly used in malicious code. Use responsibly.

## Related Blog Post
For detailed explanation, see: [Shellcode Essentials: Finding Windows APIs Dynamically](https://your-blog-url/shellcode-essentials)
