; ============================================================================
; Module A : Shell Core & FSM Command Parser
;
; By: Natpon <https://github.com/Natpon>
; ============================================================================

option casemap : none

INCLUDELIB Irvine32.lib
INCLUDELIB Kernel32.lib
INCLUDELIB User32.lib
INCLUDE Irvine32.inc
INCLUDE des.inc

.data
BUF_MAX = 100000h
prompt           BYTE "DES-SHELL> ", 0

msgUnknown       BYTE " [Error] : Unknown command!", 13, 10, 0
msgBadKey        BYTE " [Error] : Wrong key format [requirement : 16-digit hex]", 13, 10, 0
msgFileErr       BYTE " [Error] : Cannot open file.", 13, 10, 0
msgBadPad        BYTE " [Error] : Invalid padding (wrong key?)", 13, 10, 0
msgExiting       BYTE "Exiting DES Command-Line Shell...", 13, 10, 0
msgLoading       BYTE "Loading ", 0
msgOpenParen     BYTE " (", 0
msgBytesParen    BYTE " bytes)...", 13, 10, 0
msgExec          BYTE "Executing DES 16-round key generation...", 13, 10, 0
msgProc          BYTE "Processing ", 0
msgBlocks        BYTE " block(s) in ECB mode...", 13, 10, 0
msgEncOK         BYTE "File encrypted successfully -> """, 0
msgDecOK         BYTE "File decrypted successfully -> """, 0
msgFileEnd       BYTE """", 13, 10, 0
strKPrefix       BYTE "K_", 0
strKSep          BYTE ": 0x", 0
suffixEnc        BYTE ".enc", 0
suffixDec        BYTE ".dec", 0

; ---- command keywords ----
controlKEYGEN    BYTE "KEYGEN", 0
controlEncrypt   BYTE "ENCRYPT", 0
controlDecrypt   BYTE "DECRYPT", 0
controlDump      BYTE "DUMP", 0
controlStats     BYTE "STATS", 0
controlClear     BYTE "CLEAR", 0
controlExit      BYTE "EXIT", 0

; ---- buffers ----
inputBuffer      BYTE 256 dup(0)
controlToken     BYTE 64 dup(0)
arg1Token        BYTE 128 dup(0)
arg2Token        BYTE 128 dup(0)
outFileName      BYTE 160 dup(0)   ; output path, plus the .enc / .dec suffix
key64            BYTE 8 dup(0)     ; key as raw bytes
fileBuffer       BYTE BUF_MAX dup(0)
fileHandle       DWORD 0
totalLen         DWORD 0
runFlag          DWORD 1
parsePtr         DWORD 0
outBuffer        BYTE BUF_MAX dup(0)   ; ciphertext
outLen           DWORD 0               ; length including PKCS#7 padding

; ---- hex decoding scratch ----
hexDecodeBuffer  BYTE BUF_MAX / 2 dup(0)
hexDecodeLen     DWORD 0

subKeys   BYTE 96 dup(0)   ; 16 subkeys x 6 bytes
keyHi     DWORD 0
keyLo     DWORD 0

.code

main PROC
	push ebp
	mov ebp, esp
	call Clrscr

;==Loop_Program==
REPL_Loop:
	cmp runFlag, 0
	je REPL_Done
	mov edx, OFFSET prompt
	call WriteString
	; edx : point to inputBuffer
	; ecx : loop edx to read input
	; eax : real lenght
	mov edx, OFFSET inputBuffer
	mov ecx, 255
	call ReadString
	call ControlUnit
	jmp REPL_Loop

REPL_Done:
	mov edx, OFFSET msgExiting
	call WriteString
	mov esp, ebp
	pop ebp
	INVOKE ExitProcess, 0
main ENDP

; ToUpperStr: แปลง null-terminated string เป็นตัวใหญ่ทั้งหมด
; รับ: EDX = offset ของ string
ToUpperStr PROC
	push ebp
	mov ebp, esp
	push eax
	push edx

TUS_Loop:
	mov al, [edx]
	cmp al, 0
	je TUS_Done
	cmp al, 'a'
	jl TUS_Next
	cmp al, 'z'          ; Z = 7Ah if more than this mean it lower-case
	jg TUS_Next
	sub al, 20h          ; 'a'-'A' = 32 = 20h
	mov [edx], al
	;A = 41
	;a = 61
	

TUS_Next:
	inc edx
	jmp TUS_Loop

TUS_Done:
	pop edx
	pop eax
	mov esp, ebp
	pop ebp
	ret
ToUpperStr ENDP

BuildKeyDWords PROC
	push ebp
	mov ebp, esp
	push eax
	push ebx
	push esi

	mov esi, OFFSET key64
	movzx eax, BYTE PTR [esi]
	shl eax, 24
	mov ebx, eax
	movzx eax, BYTE PTR [esi+1]
	shl eax, 16
	or ebx, eax
	movzx eax, BYTE PTR [esi+2]
	shl eax, 8
	or ebx, eax
	movzx eax, BYTE PTR [esi+3]
	or ebx, eax
	mov keyHi, ebx
	movzx eax, BYTE PTR [esi+4]
	shl eax, 24
	mov ebx, eax
	movzx eax, BYTE PTR [esi+5]
	shl eax, 16
	or ebx, eax
	movzx eax, BYTE PTR [esi+6]
	shl eax, 8
	or ebx, eax
	movzx eax, BYTE PTR [esi+7]
	or ebx, eax
	mov keyLo, ebx

	pop esi
	pop ebx
	pop eax
	mov esp, ebp
	pop ebp
	ret
BuildKeyDWords ENDP

;=============================================================================
; ---- แปลง hex string เป็น key64 : ต้องเป็น 16 หลัก hex ครบ ----
;=============================================================================
HexCharToNibble PROC
	push ebp
	mov ebp, esp

	cmp al, '0'
	jl HC_Bad
	; less than 0 cause hex is 0123456789ABCDEF
	cmp al, '9'
	jg HC_CheckUpper
	; more than 9 is ABCDEF

	sub al, '0'
	jmp HC_Done

HC_CheckUpper:
	cmp al, 'A'
	jl HC_Bad
	; if less than A is no hex
	cmp al, 'F'
	jg HC_CheckLower
	; may be character is lower cose
	sub al, 'A'
	; for example A = 41 - 41 = 0
	; 0 + 10 = 10
	; Ah = 10 d
	add al, 10
	jmp HC_Done

HC_CheckLower:
	cmp al, 'a'
	jl HC_Bad
	; should not have less than this because we just check more than 'F'
	cmp al, 'f'
	jg HC_Bad
	sub al, 'a'
	add al, 10
	jmp HC_Done

HC_Bad:
	mov al, 0FFh

HC_Done:
	mov esp, ebp
	pop ebp
	ret
HexCharToNibble ENDP

CheckHexKey PROC
	push ebp
	mov ebp, esp
	push ebx
	push ecx
	push edx
	push edi

	mov al, [esi]
	cmp al, '0'                ;For example 0x1A2B3C4D5E6F7A8B   [0x : show it is hex]
	jne CHK_NoPrefix
	mov al, [esi+1]
	cmp al, 'x'

	je CHK_SkipPrefix
	cmp al, 'X'
	je CHK_SkipPrefix
	jmp CHK_NoPrefix

CHK_SkipPrefix:
	add esi, 2

CHK_NoPrefix:                ;Prefix for example 1A2B3C4D5E6F7A8B
	mov edi, OFFSET key64
	mov ecx, 8

CHK_ByteLoop:
	mov al, [esi]
	call HexCharToNibble
	; if hexcharBad it will mov al, 0FFh
	cmp al, 0FFh
	je CHK_Fail
	mov bl, al
	shl bl, 4
	inc esi
	mov al, [esi]
	call HexCharToNibble
	cmp al, 0FFh
	je CHK_Fail
	or bl, al
	mov [edi], bl
	inc esi
	inc edi

	loop CHK_ByteLoop
	cmp byte ptr [esi], 0     ; ต้องเป็น null terminator พอดี
	jne CHK_Fail
	mov eax, 1
	jmp CHK_Done

CHK_Fail:
	mov eax, 0

CHK_Done:
	pop edi
	pop edx
	pop ecx
	pop ebx
	mov esp, ebp
	pop ebp
	ret
CheckHexKey ENDP

Encrypt PROC
	push ebp
	mov ebp, esp
	pusha

;Receive argument from user
	mov esi, [parsePtr]
	mov edi, OFFSET arg1Token             ;File name
	call GetToken                         ;input {esi pointer on file name index}
	mov [parsePtr], esi
	mov edi, OFFSET arg2Token             ;key
	call GetToken

;Check key format
	mov esi, OFFSET arg2Token
	call CheckHexKey
	cmp eax, 1
	je DE_KeyOK                            ;Availiability key
	mov edx, OFFSET msgBadKey
	call WriteString
	jmp DE_Done

DE_KeyOK:
	call BuildKeyDWords
	push OFFSET subKeys
	push keyLo
	push keyHi
	call des_key_schedule
	; ----- Open File -----
	mov edx, OFFSET msgLoading
	call WriteString
	mov edx, OFFSET arg1Token
	call WriteString

	mov edx, OFFSET arg1Token
	call OpenInputFile
	cmp eax, INVALID_HANDLE_VALUE
	jne DE_OpenOK
	call Crlf
	mov edx, OFFSET msgFileErr           ;Can not open (print Error to Screen)
	call WriteString
	jmp DE_Done

DE_OpenOK:
	mov fileHandle, eax
	mov edx, OFFSET fileBuffer
	mov ecx, BUF_MAX
	call ReadFromFile
	mov totalLen, eax
	mov eax, fileHandle
	call CloseFile

	mov edx, OFFSET msgOpenParen
	call WriteString
	mov eax, totalLen
	call WriteDec
	mov edx, OFFSET msgBytesParen
	call WriteString
	mov edx, OFFSET msgExec
	call WriteString
	mov edx, OFFSET msgProc
	call WriteString


	INVOKE DES_ECB_Encrypt, OFFSET fileBuffer, totalLen, OFFSET subKeys, OFFSET outLen

    mov eax, outLen          ; ใช้ outLen เพราะรวม PKCS#7 padding แล้ว
	shr eax, 3               ; จำนวนบล็อก = outLen / 8
	call WriteDec
	mov edx, OFFSET msgBlocks
	call WriteString

	; ----- result file. (5) -----
	mov esi, OFFSET arg1Token
	mov edi, OFFSET outFileName
	call CopyStringZ
	INVOKE Str_length, ADDR outFileName ; ใช้ INVOKE แทน call
	mov edi, OFFSET outFileName
	add edi, eax
	mov esi, OFFSET suffixEnc
	call CopyStringZ

	mov edx, OFFSET outFileName
	call CreateOutputFile          ;encrypt
	mov fileHandle, eax
	mov eax, fileHandle
	mov edx, OFFSET fileBuffer     ; DES_ECB_Encrypt writes ciphertext back into fileBuffer in place
	mov ecx, outLen
	call WriteToFile
	mov eax, fileHandle
	call CloseFile

	mov edx, OFFSET msgEncOK
	call WriteString
	mov edx, OFFSET outFileName
	call WriteString
	mov edx, OFFSET msgFileEnd
	call WriteString
	call Crlf

DE_Done:
	popa
	mov esp, ebp
	pop ebp
	ret
Encrypt ENDP

Decrypt PROC
	push ebp
	mov ebp, esp
	pusha

	mov esi, [parsePtr]
	mov edi, OFFSET arg1Token             ;File name
	call GetToken
	mov [parsePtr], esi
	mov edi, OFFSET arg2Token             ;key
	call GetToken

	mov esi, OFFSET arg2Token
	call CheckHexKey
	cmp eax, 1
	je DD_KeyOK
	mov edx, OFFSET msgBadKey
	call WriteString
	jmp DD_Done

DD_KeyOK:
	call BuildKeyDWords
	push OFFSET subKeys
	push keyLo
	push keyHi
	call des_key_schedule
	mov edx, OFFSET msgLoading
	call WriteString
	mov edx, OFFSET arg1Token
	call WriteString

	mov edx, OFFSET arg1Token
	call OpenInputFile
	cmp eax, INVALID_HANDLE_VALUE
	jne DD_OpenOK
	call Crlf
	mov edx, OFFSET msgFileErr
	call WriteString
	jmp DD_Done

DD_OpenOK:
	mov fileHandle, eax
	mov edx, OFFSET fileBuffer
	mov ecx, BUF_MAX
	call ReadFromFile
	mov totalLen, eax
	mov eax, fileHandle
	call CloseFile

	mov edx, OFFSET msgOpenParen
	call WriteString
	mov eax, totalLen
	call WriteDec
	mov edx, OFFSET msgBytesParen
	call WriteString
	mov edx, OFFSET msgExec
	call WriteString
	mov edx, OFFSET msgProc
	call WriteString
	shr eax, 3
	call WriteDec
	mov edx, OFFSET msgBlocks
	call WriteString


	INVOKE DES_ECB_Decrypt, OFFSET fileBuffer, totalLen, OFFSET subKeys, OFFSET outLen

	cmp outLen, -1
	jne DD_PadOK
	mov edx, OFFSET msgBadPad
	call WriteString
	jmp DD_Done

DD_PadOK:
	mov esi, OFFSET arg1Token
	mov edi, OFFSET outFileName
	call CopyStringZ
	INVOKE Str_length, ADDR outFileName
	mov edi, OFFSET outFileName
	add edi, eax
	mov esi, OFFSET suffixDec
	call CopyStringZ

	mov edx, OFFSET outFileName
	call CreateOutputFile
	mov fileHandle, eax
	mov eax, fileHandle
	mov edx, OFFSET fileBuffer     ; DES_ECB_Decrypt writes plaintext back into fileBuffer in place
	mov ecx, outLen
	call WriteToFile
	mov eax, fileHandle
	call CloseFile

	mov edx, OFFSET msgDecOK
	call WriteString
	mov edx, OFFSET outFileName
	call WriteString
	mov edx, OFFSET msgFileEnd
	call WriteString
	call Crlf

DD_Done:
	popa
	mov esp, ebp
	pop ebp
	ret
Decrypt ENDP

;==========ข้ามช่องว่างหน้าประโยคคำสั่ง==========
SkipSpaces PROC
	push ebp
	mov ebp, esp
	push eax

SS_Loop:
	mov al, [esi]
	cmp al, 0          ;detected NULL
	je SS_Done
	cmp al, ' '
	; jump not equal that mean if found ' ' (space) no jump go to increase esi
	jne SS_Done
	inc esi
	jmp SS_Loop

SS_Done:
	pop eax
	mov esp, ebp
	pop ebp
	ret
SkipSpaces ENDP

GetToken PROC
	push ebp
	mov ebp, esp
	push eax
	call SkipSpaces
	mov al, [esi]
	cmp al, '"'
	je GT_Quoted

GT_Normal:                    ;read each character from esi then copy to edi
	mov al, [esi]
	cmp al, 0
	; if found NULL go to GT_END
	je GT_END

	cmp al, ' '
	je GT_END
	; find space 
	; encrypt uuuuu.txt
	;--------| this is space back word

	mov [edi], al
	inc esi
	inc edi
	jmp GT_Normal
	

GT_Quoted:                      ;found space forward esi
	inc esi
	; similar with GT_Normal

GT_QLoop:
	mov al, [esi]
	cmp al, 0
	je GT_END

	cmp al, '"'
	je GT_QClose

	mov [edi], al
	inc esi
	inc edi
	jmp GT_QLoop

GT_QClose:
	inc esi

GT_END:

    ; add NULL back word
	mov byte ptr [edi], 0
	pop eax
	mov esp, ebp
	pop ebp
	ret
GetToken ENDP

StrCompare PROC
	push ebp
	mov ebp, esp
	push ebx
	push esi
	push edi

SC_Loop:
	mov al, [esi]
	mov bl, [edi]
	cmp al, bl
	jne SC_NotEqual
	; found NULL
	cmp al, 0
	je SC_Equal
	inc esi
	inc edi
	jmp SC_Loop

SC_Equal:
	mov eax, 1
	jmp SC_Done

SC_NotEqual:
	mov eax, 0

SC_Done:
	pop edi
	pop esi
	pop ebx
	mov esp, ebp
	pop ebp
	ret
StrCompare ENDP

; CopyStringZ: ESI->EDI คัดลอก null-terminated string รวม null
CopyStringZ PROC
	push ebp
	mov ebp, esp
	push eax
	push esi
	push edi

CSZ_Loop:
	mov al, [esi]
	mov [edi], al
	inc esi
	inc edi
	cmp al, 0
	je CSZ_Done
	jmp CSZ_Loop

CSZ_Done:
	pop edi
	pop esi
	pop eax
	mov esp, ebp
	pop ebp
	ret
CopyStringZ ENDP

; HexDecode: แปลง hex ข้อความใน fileBuffer (totalLen ไบต์) เป็น byte ดิบ
;            ลงใน hexDecodeBuffer (คู่ hex char -> 1 byte) แล้วให้ hexDecodeLen
;            ข้ามช่องว่าง/ขึ้นบรรทัดใหม่/อักขระที่ไม่ใช่ hex ไปโดยอัตโนมัติ
HexDecode PROC
	push ebp
	mov ebp, esp
	pusha

	mov esi, OFFSET fileBuffer
	mov edi, OFFSET hexDecodeBuffer
	xor ecx, ecx            ; source index (0..totalLen-1)
	xor edx, edx            ; dest index (bytes written)
	xor ebx, ebx            ; 0 = กำลังรอ high nibble, 1 = กำลังรอ low nibble

HD_Loop:
	cmp ecx, DWORD PTR totalLen
	jae HD_Done

	movzx eax, BYTE PTR [esi + ecx]

	; skip non-hex characters (space, CR, LF, tab, เหล่าอื่นๆ)
	cmp al, '0'
	jb HD_Skip
	cmp al, '9'
	jbe HD_IsHex
	cmp al, 'A'
	jb HD_Skip
	cmp al, 'F'
	jbe HD_IsHex
	cmp al, 'a'
	jb HD_Skip
	cmp al, 'f'
	jbe HD_IsHex
	jmp HD_Skip

HD_IsHex:
	call HexCharToNibble
	cmp al, 0FFh
	je HD_Skip

	cmp ebx, 0
	jne HD_LowNibble

	; first nibble of the pair: keep it in the upper 4 bits
	shl al, 4
	mov BYTE PTR [edi + edx], al
	mov ebx, 1
	jmp HD_Next

HD_LowNibble:
	or BYTE PTR [edi + edx], al
	inc edx
	xor ebx, ebx

HD_Next:
	inc ecx
	jmp HD_Loop

HD_Skip:
	inc ecx
	jmp HD_Loop

HD_Done:
	mov DWORD PTR hexDecodeLen, edx

	popa
	mov esp, ebp
	pop ebp
	ret
HexDecode ENDP

; CmdDump: เปิดไฟล์จาก arg1Token อ่านลง fileBuffer แปลง hex เป็น byte แล้วให้ Module D พิมพ์ hex dump
CmdDump PROC
	push ebp
	mov ebp, esp
	pusha

	mov esi, [parsePtr]
	mov edi, OFFSET arg1Token             ;File name
	call GetToken
	mov [parsePtr], esi

	mov edx, OFFSET arg1Token
	call OpenInputFile
	cmp eax, INVALID_HANDLE_VALUE
	jne CMDD_OpenOK
	mov edx, OFFSET msgFileErr
	call WriteString
	jmp CMDD_Done

CMDD_OpenOK:
	mov fileHandle, eax
	mov edx, OFFSET fileBuffer
	mov ecx, BUF_MAX
	call ReadFromFile
	mov totalLen, eax
	mov eax, fileHandle
	call CloseFile

	; Dump the raw bytes as read from disk (same as ENCRYPT/DECRYPT/STATS
	; treat file content) - no hex-decode step here.
	; push order: pBuffer pushed first -> [ebp+12], length -> [ebp+8]
	push OFFSET fileBuffer
	push totalLen
	call DisplayHexDump

CMDD_Done:
	popa
	mov esp, ebp
	pop ebp
	ret
CmdDump ENDP

; CmdStats: เปิดไฟล์จาก arg1Token อ่านลง fileBuffer แล้วให้ Module D คำนวณสถิติ
CmdStats PROC
	push ebp
	mov ebp, esp
	pusha

	mov esi, [parsePtr]
	mov edi, OFFSET arg1Token             ;File name
	call GetToken
	mov [parsePtr], esi

	mov edx, OFFSET arg1Token
	call OpenInputFile
	cmp eax, INVALID_HANDLE_VALUE
	jne CMDS_OpenOK
	mov edx, OFFSET msgFileErr
	call WriteString
	jmp CMDS_Done

CMDS_OpenOK:
	mov fileHandle, eax
	mov edx, OFFSET fileBuffer
	mov ecx, BUF_MAX
	call ReadFromFile
	mov totalLen, eax
	mov eax, fileHandle
	call CloseFile

	; push order: pBuffer pushed first -> [ebp+12], length -> [ebp+8]
	push OFFSET fileBuffer
	push totalLen
	call ComputeBufferStats

CMDS_Done:
	popa
	mov esp, ebp
	pop ebp
	ret
CmdStats ENDP

; PrintHexByte: prints AL as 2 uppercase hex digits (no lookup table needed)
PrintHexByte PROC
	push ebp
	mov ebp, esp
	push eax
	push ebx

	mov bl, al
	mov al, bl
	shr al, 4
	and al, 0Fh
	cmp al, 10
	jb PHB_HighDigit
	add al, 'A'-10
	jmp PHB_HighWrite
PHB_HighDigit:
	add al, '0'
PHB_HighWrite:
	call WriteChar

	mov al, bl
	and al, 0Fh
	cmp al, 10
	jb PHB_LowDigit
	add al, 'A'-10
	jmp PHB_LowWrite
PHB_LowDigit:
	add al, '0'
PHB_LowWrite:
	call WriteChar

	pop ebx
	pop eax
	mov esp, ebp
	pop ebp
	ret
PrintHexByte ENDP

; CmdKeygen: KEYGEN <key> -> validate the key, run the key schedule, print K1..K16
CmdKeygen PROC
	push ebp
	mov ebp, esp
	pusha

	mov esi, [parsePtr]
	mov edi, OFFSET arg1Token             ;key
	call GetToken
	mov [parsePtr], esi

	mov esi, OFFSET arg1Token
	call CheckHexKey
	cmp eax, 1
	je CKG_KeyOK
	; if key not ok it will return 0 from eax
	mov edx, OFFSET msgBadKey
	call WriteString
	jmp CKG_Done

CKG_KeyOK:
	call BuildKeyDWords
	push OFFSET subKeys
	push keyLo
	push keyHi
	call des_key_schedule      ; from module Byte
	; recieve keyLo 32byte
	; recieve keyHi 32byte


	mov ecx, 0                 ; round index 0..15
CKG_Loop:
	cmp ecx, 16
	jge CKG_Done

	mov edx, OFFSET strKPrefix
	call WriteString
	mov eax, ecx
	inc eax
	call WriteDec
	mov edx, OFFSET strKSep
	call WriteString

	push ecx
	mov eax, ecx
	mov ebx, 6
	mul ebx
	mov esi, OFFSET subKeys
	add esi, eax
	mov al, [esi]
	call PrintHexByte
	mov al, [esi+1]
	call PrintHexByte
	mov al, [esi+2]
	call PrintHexByte
	mov al, [esi+3]
	call PrintHexByte
	mov al, [esi+4]
	call PrintHexByte
	mov al, [esi+5]
	call PrintHexByte
	pop ecx

	call Crlf
	inc ecx
	jmp CKG_Loop

CKG_Done:
	popa
	mov esp, ebp
	pop ebp
	ret
CmdKeygen ENDP

ControlUnit PROC
	push ebp
	mov ebp, esp
	pusha             ;push all

	mov esi, OFFSET inputBuffer   ;space for file name
	mov edi, OFFSET controlToken
	call GetToken
	; edi = controlToken
	; edi = GetToken
	; esi = test.txt 12345678..


	mov [parsePtr], esi
	; put test.txt 12345678.. to [parsePtr]

	mov edx, OFFSET controlToken
	call ToUpperStr


	mov al, [controlToken]
	cmp al, 0                ;found NULL go to To_Done
	je To_Done
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;controlToken : First word that cutted by TOKEN                         ;
; 7 options : Encrypt , Decrypt , Dump , Stats , Clear , Exit , Unknow  ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

Decision:
	mov esi, OFFSET controlToken
	mov edi, OFFSET controlKEYGEN
	call StrCompare
	; if equal eax will be 1
	; if not equal eax will be 0
	cmp eax, 1
	je To_Keygen

	mov esi, OFFSET controlToken
	mov edi, OFFSET controlEncrypt
	call StrCompare
	cmp eax, 1
	je To_Encrypt

	mov esi, OFFSET controlToken
	mov edi, OFFSET controlDecrypt
	call StrCompare
	cmp eax, 1
	je To_Decrypt

	mov esi, OFFSET controlToken
	mov edi, OFFSET controlDump
	call StrCompare
	cmp eax, 1
	je To_Dump

	mov esi, OFFSET controlToken
	mov edi, OFFSET controlStats
	call StrCompare
	cmp eax, 1
	je To_Stats

	mov esi, OFFSET controlToken
	mov edi, OFFSET controlClear
	call StrCompare
	cmp eax, 1
	je To_Clear

	mov esi, OFFSET controlToken
	mov edi, OFFSET controlExit
	call StrCompare
	cmp eax, 1
	je To_Exit

	jmp To_Unknow

To_Keygen:
	call CmdKeygen
	call Crlf
	jmp To_Done

To_Encrypt:
	call Encrypt
	call Crlf
	jmp To_Done

To_Exit:
	mov runFlag, 0
	jmp To_Done

To_Decrypt:
	call Decrypt
	call Crlf
	jmp To_Done

To_Dump:
	;DUMP <filename> : พิมพ์ hex dump ของไฟล์
	call CmdDump
	call Crlf
	jmp To_Done

To_Stats:
	;STATS <filename> : แสดงสถิติ/ความถี่ของ byte ในไฟล์
	call CmdStats
	call Crlf
	jmp To_Done

To_Clear:
	call Clrscr
	jmp To_Done

To_Unknow:
	mov edx, OFFSET msgUnknown
	call Crlf
	call WriteString

;==========================================================
To_Done:
	popa
	mov esp, ebp
	pop ebp
	ret
ControlUnit ENDP

END main
