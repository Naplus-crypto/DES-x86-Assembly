# x86 Assembly DES Command-Line Shell & File Encryption Engine
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An implementation of a Command-Line Shell and File Encryption Engine using Classical DES (Data Encryption Standard) written in **x86 Assembly (32-bit Protected Mode, MASM Standard)**. Developed as a coursework project for 01476105 Computer Organization and Assembly Language at King Mongkut's Institute of Technology Ladkrabang (KMITL).

---

## 👥 Project Team & Contributions
* **Mr. Natthawat Kittanavet** - Module A (Shell Core & FSM Command Parser)
* **Mr. Surajeeth Taladtanee** - Module B (DES Key Schedule Generator)
* **Mr. Patiphat Prathumwan** - Module C (DES 16-Round Feistel Core Engine)
* **Mr. Prakrit kwanphatthalung** - Module D (Memory Dumper & Buffer Analytics)

---

## 🚀 Features & Architecture
The application runs as an interactive REPL (Read-Eval-Print Loop) shell supporting the following commands:
1. **`KEYGEN`**: Generates and displays all 16 subkeys ($K_1 - K_{16}$) from a 64-bit key.
2. **`ENCRYPT <file> <key>`**: Encrypts a plaintext file in ECB mode with PKCS#7 padding.
3. **`DECRYPT <file> <key>`**: Decrypts a ciphertext file.
4. **`DUMP <file>`**: Displays file contents in both Hexadecimal and ASCII formats with offset addresses.
5. **`STATS <file>`**: Generates a 256-bin histogram and analyzes entropy/byte patterns.
6. **`CLEAR`**: Clears the console screen.
7. **`EXIT`**: Terminates the shell.

---

## ⚙️ Technical Constraints & Compliance
* **Target Architecture**: x86 Assembly (32-bit Protected Mode) using MASM and Irvine32 Library.
* **Low-Level Control**: Strict adherence to low-level conditional jumps (`CMP`, `TEST`, `JE`, `JNE`, etc.) without high-level control directives (`.IF`, `WHILE`, `.REPEAT`) inside critical cipher and parser loops.
* **Stack Frame Standard**: Standard stack frame conventions (`push ebp`, `mov ebp, esp`, `pop ebp`) implemented across all procedures, passing return values via `EAX`.
* **Zero External Crypto Libraries**: All routines—including Initial Permutation (IP), Key Schedule, 16 Feistel Rounds, S-Box lookups, and Inverse Permutation—are implemented entirely from scratch in assembly.

---

## 🧪 Verification & Test Vectors
Tested and validated against official NIST DES test vectors:
* **Plaintext1 (Hex)**: `5468652071756663` "The qufc"
* **Plaintext2 (Hex)**: `6B2062726F776E20` "k brown"
* **Plaintext3 (Hex)**: `666F78206A756D70` "fox jump"
* **Sample text (Hex)**: `0123456789ABCDEF`
* **Key (Hex)**: `0123456789ABCDEF`
* **Sample Key (Hex)**: `133457799BBCDFF1`
* **Expected Ciphertext1 (Hex)**: `A28E91724C4BBA31`
* **Expected Ciphertext2 (Hex)**: `167E47EC24F71D63`
* **Expected Ciphertext3 (Hex)**: `2C1A917234425365`
* **Expected Sample Cipher (Hex)**: `85E813540F0AB405`

---

## 🛠️ Requirements & Environment
* Microsoft Macro Assembler (MASM) / Visual Studio Build Tools
* Irvine32 Library
* Windows 10 / 11 (32-bit / 64-bit with 32-bit subsystem support)

---

## How to run
First, assemble the four source files using MASM:
```
ml /nologo /Sn /Sa /Zi /c /coff /Fl /I "Irvine" Module_A.asm Module_B.asm Module_C.asm Module_D.asm
```
Second, link the object files against the Irvine32 library to produce the executable:
```
link /SUBSYSTEM:CONSOLE /LIBPATH:"Irvine" /OPT:NOREF /OPT:NOICF /DEBUG /NOLOGO /OUT:des.exe Module_A.obj Module_B.obj Module_C.obj Module_D.obj Irvine32.lib
```
Then, run the program:
```
.\des.exe
```
