; ============================================================================
; Module D : Memory Dumper & Buffer Analytics
; By PrakritPrad <https://github.com/PrakritPrad>
;
;   DisplayHexDump     - hex dump, 16 bytes per line
;   ComputeBufferStats - histogram + size / entropy / top-5 report
;
; STDCALL, callee cleans: [ebp+8] = dataLen, [ebp+12] = buffer, returns EAX
; ============================================================================

option casemap : none

INCLUDELIB Irvine32.lib
INCLUDELIB Kernel32.lib
INCLUDELIB User32.lib
INCLUDE Irvine32.inc

PUBLIC DisplayHexDump
PUBLIC ComputeBufferStats

.data

hexHeader   BYTE " [Address]  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII", 0
hexDigits   BYTE "0123456789ABCDEF", 0
msgline     BYTE " ------------------------------------------------------------------", 13, 10, 0

strTotal    BYTE "Total File Size: ", 0
strBytes    BYTE " Bytes", 13, 10, 0
strEntropy  BYTE "Entropy Statistics: ", 0
strPass     BYTE "High Diffusion (Ciphertext Uniformity Check PASSED)", 13, 10, 0
strFail     BYTE "Low Diffusion (Ciphertext Uniformity Check FAILED)", 13, 10, 0
strTop      BYTE "Top Byte Occurrences:", 13, 10, 0
strRankDot  BYTE ". [0x", 0
strHexCol   BYTE "] : ", 0
strOcc      BYTE " occurrences [", 0
strBarEnd   BYTE "]", 13, 10, 0

bins        DWORD 256 DUP(0)        ; bins[v] = count of byte v
firstSeen   DWORD 256 DUP(0)        ; first offset where v appears
usedFlag    BYTE  256 DUP(0)        ; v already ranked
topValue    BYTE  5 DUP(0)
topCount    DWORD 5 DUP(0)

numTemp     DWORD 0                ; integer -> FPU bridge
totTemp     DWORD 0
entropyVal  REAL8 0.0
threshVal   REAL8 0.0
ENT_CAP     REAL8 8.0
ENT_SCALE   REAL8 0.75
STAR_MAX    EQU 20

.code

; ---------------------------------------------------------------------------
; WriteHexByteFixed - print AL as 2 uppercase hex digits
;
; Input  : AL = byte value
; Returns: nothing (output goes to the console)
; ---------------------------------------------------------------------------
WriteHexByteFixed PROC
    push ebp
    mov  ebp, esp
    pushad

    movzx eax, al
    mov   edx, eax
    mov   ebx, OFFSET hexDigits
    shr   eax, 4
    and   eax, 0Fh
    mov   al, BYTE PTR [ebx + eax]
    call  WriteChar
    mov   eax, edx
    and   eax, 0Fh
    mov   al, BYTE PTR [ebx + eax]
    call  WriteChar

    popad
    mov  esp, ebp
    pop  ebp
    ret
WriteHexByteFixed ENDP

; ---------------------------------------------------------------------------
; WriteHex32Fixed - print EAX as 8 uppercase hex digits
;
; Input  : EAX = value to print
; Returns: nothing (output goes to the console)
; ---------------------------------------------------------------------------
WriteHex32Fixed PROC
    push ebp
    mov  ebp, esp
    pushad

    mov   edx, eax
    mov   ebx, OFFSET hexDigits
    mov   ecx, 8
hex32_loop:
    rol   edx, 4
    mov   eax, edx
    and   eax, 0Fh
    mov   al, BYTE PTR [ebx + eax]
    call  WriteChar
    loop  hex32_loop

    popad
    mov  esp, ebp
    pop  ebp
    ret
WriteHex32Fixed ENDP

; ---------------------------------------------------------------------------
; DisplayHexDump - classic hex dump, ASCII column on the right
;
;   00000000  54 68 65 20 71 75 66 63  | The qufc
;
; Stack arguments:
;   [ebp+8]  = length (bytes)
;   [ebp+12] = pointer to buffer
; Returns   : EAX = 0
;
; Locals:
;   [ebp-4] = offset of the current row
;   [ebp-8] = real bytes in the current row (1..16)
; ---------------------------------------------------------------------------
DisplayHexDump PROC, dataLen:DWORD, buffer:PTR BYTE
    sub  esp, 8
    pushad

    mov  esi, DWORD PTR [ebp+12]
    mov  ebx, DWORD PTR [ebp+8]

    cmp  ebx, 0
    je   DHD_done

    mov  edx, OFFSET hexHeader
    call WriteString
    call Crlf
    mov  edx, OFFSET msgline
    call WriteString

    mov  DWORD PTR [ebp-4], 0

DHD_row_loop:                          ; one line per 16 bytes
    mov  eax, DWORD PTR [ebp-4]
    cmp  eax, ebx
    jae  DHD_done

    mov  eax, ebx                    ; bytes in row = min(16, remaining)
    sub  eax, DWORD PTR [ebp-4]
    cmp  eax, 16
    jbe  DHD_row_len_ok
    mov  eax, 16
DHD_row_len_ok:
    mov  DWORD PTR [ebp-8], eax

    mov  al, ' '                      ; 1 leading space, as in the spec sample
    call WriteChar
    mov  eax, DWORD PTR [ebp-4]
    call WriteHex32Fixed
    mov  al, ' '
    call WriteChar
    mov  al, ' '
    call WriteChar
    mov  al, ' '
    call WriteChar

    xor  ecx, ecx
DHD_hex_loop:                          ; 16 slots of "XX "
    cmp  ecx, 16
    jae  DHD_hex_done
    cmp  ecx, DWORD PTR [ebp-8]
    jae  DHD_hex_pad
    mov  edx, esi
    add  edx, DWORD PTR [ebp-4]
    movzx eax, BYTE PTR [edx + ecx]
    call WriteHexByteFixed
    mov  al, ' '
    call WriteChar
    jmp  DHD_hex_next

DHD_hex_pad:                           ; pad the short last line
    mov  al, ' '
    call WriteChar
    mov  al, ' '
    call WriteChar
    mov  al, ' '
    call WriteChar

DHD_hex_next:
    inc  ecx
    jmp  DHD_hex_loop
DHD_hex_done:

    mov  al, '|'
    call WriteChar
    mov  al, ' '
    call WriteChar

    xor  ecx, ecx
DHD_ascii_loop:                        ; printable 20h..7Eh, else '.'
    cmp  ecx, 16
    jae  DHD_ascii_done
    cmp  ecx, DWORD PTR [ebp-8]
    jae  DHD_ascii_pad
    mov  edx, esi
    add  edx, DWORD PTR [ebp-4]
    movzx eax, BYTE PTR [edx + ecx]
    cmp  al, 20h
    jb   DHD_not_print
    cmp  al, 7Eh
    ja   DHD_not_print
    call WriteChar
    jmp  DHD_ascii_next

DHD_not_print:
    mov  al, '.'
    call WriteChar
    jmp  DHD_ascii_next

DHD_ascii_pad:
    mov  al, ' '
    call WriteChar

DHD_ascii_next:
    inc  ecx
    jmp  DHD_ascii_loop
DHD_ascii_done:

    call Crlf
    add  DWORD PTR [ebp-4], 16
    jmp  DHD_row_loop

DHD_done:
    popad
    mov  esp, ebp
    xor  eax, eax
    ret  8
DisplayHexDump ENDP

; ---------------------------------------------------------------------------
; ComputeBufferStats - size, entropy verdict, 5 most common bytes
;
; Stack arguments:
;   [ebp+8]  = length (bytes)
;   [ebp+12] = pointer to buffer
; Returns   : EAX = 0
;
; Locals:
;   [ebp-4]  = best count while ranking
;   [ebp-8]  = byte value of that best count
;   [ebp-12] = number of ranks actually found
;   [ebp-16] = first-appearance offset of that byte
; ---------------------------------------------------------------------------
ComputeBufferStats PROC, dataLen:DWORD, buffer:PTR BYTE
    sub  esp, 16
    pushad

    mov  esi, DWORD PTR [ebp+12]
    mov  ebx, DWORD PTR [ebp+8]

    cmp  ebx, 0
    je   CBS_done

    lea  edi, bins                     ; these live in .data, clear them
    xor  eax, eax
    mov  ecx, 256
    rep  stosd
    lea  edi, usedFlag
    mov  ecx, 256
    rep  stosb

CBS_scan_bytes:                        ; pass 1: bins[byte]++ + first offset
    xor  ecx, ecx
CBS_scan_bytes_loop:
    cmp  ecx, ebx
    jae  CBS_scan_bytes_done
    movzx eax, BYTE PTR [esi + ecx]
    inc  DWORD PTR [bins + eax*4]
    cmp  DWORD PTR [bins + eax*4], 1
    jne  CBS_scan_bytes_next
    mov  DWORD PTR [firstSeen + eax*4], ecx
CBS_scan_bytes_next:
    inc  ecx
    jmp  CBS_scan_bytes_loop
CBS_scan_bytes_done:

    mov  edx, OFFSET strTotal
    call WriteString
    mov  eax, ebx
    call WriteDec
    mov  edx, OFFSET strBytes
    call WriteString

    mov  totTemp, ebx
    fldz
    xor  edi, edi

CBS_ent_loop:                          ; H = -SUM( p * log2(p) ), p = count/total
    cmp  edi, 256
    jae  CBS_ent_done
    mov  eax, DWORD PTR [bins + edi*4]
    test eax, eax
    jz   CBS_ent_next
    mov  numTemp, eax
    fild DWORD PTR numTemp
    fild DWORD PTR totTemp
    fdivp st(1), st(0)                ; st = p
    fld  st(0)
    fld1
    fxch st(1)                        ; fyl2x: st(1) * log2(st(0)), then pop
    fyl2x
    fmulp st(1), st(0)                ; p * log2(p)
    faddp st(1), st(0)                ; acc += ...
CBS_ent_next:
    inc  edi
    jmp  CBS_ent_loop
CBS_ent_done:
    fchs
    fstp entropyVal

    ; threshold = 0.75 * min(8, log2(total)) -- a short file cannot reach 8 bits
    fld1
    fild DWORD PTR totTemp
    fyl2x
    fcom QWORD PTR ENT_CAP
    jbe  CBS_thr_scale
    fld  QWORD PTR ENT_CAP
    fstp ST(1)
CBS_thr_scale:
    fmul QWORD PTR ENT_SCALE
    fstp QWORD PTR threshVal

    mov  edx, OFFSET strEntropy
    call WriteString
    fld  QWORD PTR threshVal
    fld  QWORD PTR entropyVal
    fcompp
    fnstsw ax
    test ah, 01h                      ; C0 = 1 <=> entropy < threshold
    jnz  CBS_low_diff
    mov  edx, OFFSET strPass
    jmp  CBS_ent_disp
CBS_low_diff:
    mov  edx, OFFSET strFail
CBS_ent_disp:
    call WriteString

    mov  edx, OFFSET strTop
    call WriteString

    mov  DWORD PTR [ebp-12], 0
    mov  ebx, 0

CBS_find_loop:                         ; 5 passes, each picks the largest
    cmp  ebx, 5                       ; unused bin; ties go to the value
    jae  CBS_find_done                ; that appeared first
    xor  eax, eax
    mov  DWORD PTR [ebp-4], eax
    mov  DWORD PTR [ebp-8], eax
    mov  DWORD PTR [ebp-16], 0FFFFFFFFh
    xor  edi, edi

CBS_pick_loop:                         ; scan 256 bins for the best candidate
    cmp  edi, 256
    jae  CBS_pick_done
    mov  al, BYTE PTR [usedFlag + edi]
    test al, al
    jnz  CBS_pick_next
    mov  eax, DWORD PTR [bins + edi*4]
    cmp  eax, DWORD PTR [ebp-4]
    ja   CBS_pick_take
    jb   CBS_pick_next
    test eax, eax
    jz   CBS_pick_next
    mov  eax, DWORD PTR [firstSeen + edi*4]
    cmp  eax, DWORD PTR [ebp-16]
    jae  CBS_pick_next
CBS_pick_take:
    mov  eax, DWORD PTR [bins + edi*4]
    mov  DWORD PTR [ebp-4], eax
    mov  DWORD PTR [ebp-8], edi
    mov  eax, DWORD PTR [firstSeen + edi*4]
    mov  DWORD PTR [ebp-16], eax
CBS_pick_next:
    inc  edi
    jmp  CBS_pick_loop
CBS_pick_done:
    cmp  DWORD PTR [ebp-4], 0
    je   CBS_find_done
    mov  eax, DWORD PTR [ebp-8]
    mov  BYTE PTR [topValue + ebx], al
    mov  eax, DWORD PTR [ebp-4]
    mov  DWORD PTR [topCount + ebx*4], eax
    mov  eax, DWORD PTR [ebp-8]
    mov  BYTE PTR [usedFlag + eax], 1
    inc  DWORD PTR [ebp-12]
    inc  ebx
    jmp  CBS_find_loop
CBS_find_done:

CBS_print_loop:                        ; 1. [0x54] : 3 occurrences [***]
    mov  ebx, 0
CBS_print_next:
    cmp  ebx, DWORD PTR [ebp-12]
    jae  CBS_print_done
    mov  eax, ebx
    inc  eax
    call WriteDec
    mov  edx, OFFSET strRankDot
    call WriteString
    movzx eax, BYTE PTR [topValue + ebx]
    call WriteHexByteFixed
    mov  edx, OFFSET strHexCol
    call WriteString
    mov  eax, DWORD PTR [topCount + ebx*4]
    call WriteDec
    mov  edx, OFFSET strOcc
    call WriteString
    mov  ecx, DWORD PTR [topCount + ebx*4]
    cmp  ecx, STAR_MAX
    jbe  CBS_bar_len_ok
    mov  ecx, STAR_MAX
CBS_bar_len_ok:
CBS_bar_loop:                          ; one star per hit, capped at STAR_MAX
    test ecx, ecx
    jz   CBS_bar_done
    mov  al, '*'
    call WriteChar
    dec  ecx
    jmp  CBS_bar_loop
CBS_bar_done:
    mov  edx, OFFSET strBarEnd
    call WriteString
    inc  ebx
    jmp  CBS_print_next
CBS_print_done:

CBS_done:
    popad
    mov  esp, ebp
    xor  eax, eax
    ret  8
ComputeBufferStats ENDP

END
