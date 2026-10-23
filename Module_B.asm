; ============================================================================
; Module B : DES Key Schedule Generator
;
; By: yod2803 <https://github.com/yod2803>.
; ============================================================================

OPTION CASEMAP:NONE

INCLUDE Irvine32.inc
INCLUDE des.inc

.data

; ================================================================
; DES Key Schedule Constants
; ================================================================

; PC-1 entries used to generate the 28-bit C value.
PC1_C BYTE 57, 49, 41, 33, 25, 17, 9, 1
      BYTE 58, 50, 42, 34, 26, 18, 10, 2
      BYTE 59, 51, 43, 35, 27, 19, 11, 3
      BYTE 60, 52, 44, 36

; PC-1 entries used to generate the 28-bit D value.
PC1_D BYTE 63, 55, 47, 39, 31, 23, 15, 7
      BYTE 62, 54, 46, 38, 30, 22, 14, 6
      BYTE 61, 53, 45, 37, 29, 21, 13, 5
      BYTE 28, 20, 12, 4

; PC-2 table used to generate each 48-bit round subkey.
PC2 BYTE 14, 17, 11, 24, 1, 5, 3, 28
    BYTE 15, 6, 21, 10, 23, 19, 12, 4
    BYTE 26, 8, 16, 7, 27, 20, 13, 2
    BYTE 41, 52, 31, 37, 47, 55, 30, 40
    BYTE 51, 45, 33, 48, 44, 49, 39, 56
    BYTE 34, 53, 46, 42, 50, 36, 29, 32

; Number of left rotations for DES rounds 1 through 16.
SHIFTS BYTE 1, 1, 2, 2, 2, 2, 2, 2
       BYTE 1, 2, 2, 2, 2, 2, 2, 1


.code

; ================================================================
; rol28
;
; Performs a left circular rotation on a 28-bit value.
;
; Parameters:
;   val       [ebp+8]  - input value
;   shift_cnt [ebp+12] - rotation count
;
; Returns:
;   EAX - rotated 28-bit value
; ================================================================
rol28 PROC
    push ebp
    mov ebp, esp
    push ebx

    mov eax, DWORD PTR [ebp + 8]
    mov ecx, DWORD PTR [ebp + 12]

    ; Shift left and keep only the lower 28 bits.
    shl eax, cl
    and eax, 0FFFFFFFh

    ; Move the bits that wrapped around to the right side.
    mov ebx, DWORD PTR [ebp + 8]
    mov ecx, 28
    sub ecx, DWORD PTR [ebp + 12]
    shr ebx, cl

    ; Combine both parts.
    or eax, ebx

    pop ebx
    mov esp, ebp
    pop ebp
    ret 8
rol28 ENDP

; ================================================================
; permute_PC1
;
; Selects 28 bits from the original 64-bit DES key.
; The supplied table must be PC1_C or PC1_D.
;
; Parameters:
;   key_hi [ebp+8]  - upper 32 bits of the key
;   key_lo [ebp+12] - lower 32 bits of the key
;   pTable [ebp+16] - PC-1 table address
;
; Returns:
;   EAX - selected 28-bit value
; ================================================================
permute_PC1 PROC
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    mov esi, DWORD PTR [ebp + 16]
    xor edi, edi
    xor ebx, ebx

pc1_loop:
    cmp edi, 28
    jge pc1_done

    ; Read the next bit position from the table.
    movzx eax, BYTE PTR [esi + edi]

    cmp eax, 32
    jg pc1_from_lo

    ; Read a bit from the upper 32-bit half.
    mov ecx, 32
    sub ecx, eax
    mov edx, DWORD PTR [ebp + 8]
    shr edx, cl
    and edx, 1
    jmp pc1_bit_ready

pc1_from_lo:
    ; Read a bit from the lower 32-bit half.
    mov ecx, 64
    sub ecx, eax
    mov edx, DWORD PTR [ebp + 12]
    shr edx, cl
    and edx, 1

pc1_bit_ready:
    ; Append the selected bit to the result.
    shl ebx, 1
    or ebx, edx

    inc edi
    jmp pc1_loop

pc1_done:
    mov eax, ebx
    pop edi
    pop esi
    pop ebx
    mov esp, ebp
    pop ebp
    ret 12
permute_PC1 ENDP

; ================================================================
; permute_PC2
;
; Selects 48 bits from C_i || D_i using PC-2.
;
; Parameters:
;   c_val [ebp+8]  - current 28-bit C value
;   d_val [ebp+12] - current 28-bit D value
;   pTable [ebp+16] - PC-2 table address
;
; Returns:
;   EDX:EAX - 48-bit subkey
;             EAX contains the lower 32 bits.
;             The lower 16 bits of EDX contain the upper 16 bits.
; ================================================================
permute_PC2 PROC
    push ebp
    mov ebp, esp
    sub esp, 8                 ; [ebp-4] = upper accumulator
                               ; [ebp-8] = lower accumulator
    push ebx
    push esi
    push edi

    mov DWORD PTR [ebp - 4], 0
    mov DWORD PTR [ebp - 8], 0

    mov esi, DWORD PTR [ebp + 16]
    xor edi, edi

pc2_loop:
    cmp edi, 48
    jge pc2_done

    ; Read the next PC-2 position.
    movzx eax, BYTE PTR [esi + edi]

    cmp eax, 28
    jg pc2_from_D

    ; Positions 1 through 28 refer to C.
    mov ecx, 28
    sub ecx, eax
    mov edx, DWORD PTR [ebp + 8]
    shr edx, cl
    and edx, 1
    jmp pc2_bit_ready

pc2_from_D:
    ; Positions 29 through 56 refer to D.
    mov ecx, 56
    sub ecx, eax
    mov edx, DWORD PTR [ebp + 12]
    shr edx, cl
    and edx, 1

pc2_bit_ready:
    ; Shift the 48-bit accumulator left by one bit.
    mov eax, DWORD PTR [ebp - 4]
    shl eax, 1

    ; Move the carry from the lower half to the upper half.
    mov ebx, DWORD PTR [ebp - 8]
    shr ebx, 31
    or eax, ebx
    mov DWORD PTR [ebp - 4], eax

    ; Shift the lower half and append the selected bit.
    mov ebx, DWORD PTR [ebp - 8]
    shl ebx, 1
    or ebx, edx
    mov DWORD PTR [ebp - 8], ebx

    inc edi
    jmp pc2_loop

pc2_done:
    mov eax, DWORD PTR [ebp - 8]
    mov edx, DWORD PTR [ebp - 4]

    pop edi
    pop esi
    pop ebx
    mov esp, ebp
    pop ebp
    ret 12
permute_PC2 ENDP

; ================================================================
; des_key_schedule
;
; Generates all 16 DES round subkeys.
;
; Parameters:
;   key_hi   [ebp+8]  - upper 32 bits of the original key
;   key_lo   [ebp+12] - lower 32 bits of the original key
;   pSubkeys [ebp+16] - destination buffer
;
; Returns:
;   EAX = 0 on success
; ================================================================
PUBLIC des_key_schedule
des_key_schedule PROC, keyHi:DWORD, keyLo:DWORD, pSubkeys:PTR BYTE
    sub esp, 12                ; [ebp-4]  = current C
                               ; [ebp-8]  = current D
                               ; [ebp-12] = round index
    push ebx
    push esi
    push edi

    ; Generate C0 using PC-1.
    push OFFSET PC1_C
    push DWORD PTR [ebp + 12]
    push DWORD PTR [ebp + 8]
    call permute_PC1
    mov DWORD PTR [ebp - 4], eax

    ; Generate D0 using PC-1.
    push OFFSET PC1_D
    push DWORD PTR [ebp + 12]
    push DWORD PTR [ebp + 8]
    call permute_PC1
    mov DWORD PTR [ebp - 8], eax

    mov DWORD PTR [ebp - 12], 0

round_loop:
    cmp DWORD PTR [ebp - 12], 16
    jge round_done

    ; Read the shift count for this round.
    mov esi, DWORD PTR [ebp - 12]
    movzx ebx, BYTE PTR [SHIFTS + esi]

    ; Rotate C and D.
    push ebx
    push DWORD PTR [ebp - 4]
    call rol28
    mov DWORD PTR [ebp - 4], eax

    push ebx
    push DWORD PTR [ebp - 8]
    call rol28
    mov DWORD PTR [ebp - 8], eax

    ; Generate the current subkey using PC-2.
    push OFFSET PC2
    push DWORD PTR [ebp - 8]
    push DWORD PTR [ebp - 4]
    call permute_PC2

        ; Store the subkey in a 6-byte slot (MSB-first byte order for Module C)
    push eax
    push edx

    mov edi, DWORD PTR [ebp + 16]
    mov eax, DWORD PTR [ebp - 12]
    lea eax, [eax + eax*2]
    shl eax, 1
    add edi, eax

    pop edx
    pop eax

    mov bl, dh
    mov [edi], bl
    mov bl, dl
    mov [edi+1], bl
    mov ebx, eax
    shr ebx, 24
    mov [edi+2], bl
    mov ebx, eax
    shr ebx, 16
    mov [edi+3], bl
    mov ebx, eax
    shr ebx, 8
    mov [edi+4], bl
    mov [edi+5], al

    inc DWORD PTR [ebp - 12]
    jmp round_loop

round_done:
    xor eax, eax               ; EAX = 0 on success
    pop edi
    pop esi
    pop ebx
    ret  12                    ; STDCALL: remove the 3 DWORD arguments
des_key_schedule ENDP

END
