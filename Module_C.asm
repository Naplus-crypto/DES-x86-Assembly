; ============================================================================
; Module C : DES 16-Round Feistel Core Engine
;
; By: Naplus-crypto <https://github.com/Naplus-crypto>
;
; Implements:
;   - Initial Permutation (IP) and Inverse Initial Permutation (IP^-1)
;   - Cipher function f(R,K): Expansion (E) -> XOR with Ki -> S-Box lookups -> Permutation (P)
;   - 16-round Feistel network (encrypt = forward key order, decrypt = reverse key order)
;   - ECB mode block driver
;   - PKCS#7 padding / unpadding
;
; Assumes Module B has already produced a 16 x 6-byte subkey schedule
; (SubKeys: 16 blocks of 48 bits each, 96 bytes total, K1 first).
;
; ทุก bit operation เขียนเองด้วย AND/OR/SHL/SHR/CMP/JMP
; ============================================================================

OPTION CASEMAP:NONE

INCLUDE Irvine32.inc
INCLUDE des.inc

.DATA

; ---- Initial Permutation table (64 entries, 1-based bit positions) --------
IP_TABLE BYTE 58,50,42,34,26,18,10, 2
         BYTE 60,52,44,36,28,20,12, 4
         BYTE 62,54,46,38,30,22,14, 6
         BYTE 64,56,48,40,32,24,16, 8
         BYTE 57,49,41,33,25,17, 9, 1
         BYTE 59,51,43,35,27,19,11, 3
         BYTE 61,53,45,37,29,21,13, 5
         BYTE 63,55,47,39,31,23,15, 7

; ---- Inverse Initial Permutation table (64 entries) -----------------------
IPINV_TABLE BYTE 40, 8,48,16,56,24,64,32
            BYTE 39, 7,47,15,55,23,63,31
            BYTE 38, 6,46,14,54,22,62,30
            BYTE 37, 5,45,13,53,21,61,29
            BYTE 36, 4,44,12,52,20,60,28
            BYTE 35, 3,43,11,51,19,59,27
            BYTE 34, 2,42,10,50,18,58,26
            BYTE 33, 1,41, 9,49,17,57,25

; ---- Expansion table E (32 -> 48 bits) -------------------------------------
E_TABLE BYTE 32, 1, 2, 3, 4, 5
        BYTE  4, 5, 6, 7, 8, 9
        BYTE  8, 9,10,11,12,13
        BYTE 12,13,14,15,16,17
        BYTE 16,17,18,19,20,21
        BYTE 20,21,22,23,24,25
        BYTE 24,25,26,27,28,29
        BYTE 28,29,30,31,32, 1

; ---- Permutation table P (32 -> 32 bits) -----------------------------------
P_TABLE BYTE 16, 7,20,21,29,12,28,17
        BYTE  1,15,23,26, 5,18,31,10
        BYTE  2, 8,24,14,32,27, 3, 9
        BYTE 19,13,30, 6,22,11, 4,25

; ---- S-Boxes, S1..S8, each flattened 4 rows x 16 cols = 64 bytes ----------
; Indexed as SBOX[boxIndex*64 + row*16 + col]
SBOX BYTE 14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7   ; S1 row0
     BYTE  0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8   ; S1 row1
     BYTE  4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0   ; S1 row2
     BYTE 15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13   ; S1 row3

     BYTE 15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10   ; S2
     BYTE  3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5
     BYTE  0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15
     BYTE 13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9

     BYTE 10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8   ; S3
     BYTE 13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1
     BYTE 13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7
     BYTE  1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12

     BYTE  7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15   ; S4
     BYTE 13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9
     BYTE 10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4
     BYTE  3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14

     BYTE  2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9   ; S5
     BYTE 14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6
     BYTE  4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14
     BYTE 11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3

     BYTE 12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11   ; S6
     BYTE 10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8
     BYTE  9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6
     BYTE  4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13

     BYTE  4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1   ; S7
     BYTE 13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6
     BYTE  1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2
     BYTE  6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12

     BYTE 13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7   ; S8
     BYTE  1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2
     BYTE  7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8
     BYTE  2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11

.CODE

; ============================================================================
; ExtractBit
;   Returns bit #bitNum (1-based, bit 1 = MSB of byte 0) from srcBuf in EAX.
; ============================================================================
ExtractBit PROC USES ebx ecx edx esi, srcBuf:PTR BYTE, bitNum:DWORD
    mov     eax, bitNum
    dec     eax                 ; zero-based index
    mov     ecx, eax
    shr     eax, 3              ; byte offset = index / 8
    and     ecx, 7              ; bit offset from left within byte
    mov     esi, srcBuf
    add     esi, eax
    movzx   ebx, BYTE PTR [esi]
    mov     edx, 7
    sub     edx, ecx            ; shift so that target bit lands in bit0
    mov     cl, dl
    shr     ebx, cl
    and     ebx, 1
    mov     eax, ebx
    ret
ExtractBit ENDP

; ============================================================================
; SetBit
;   Sets (or clears) bit #bitNum (1-based, bit1 = MSB of byte0) in destBuf.
;   Destination buffer is expected to be zeroed beforehand by the caller.
; ============================================================================
SetBit PROC USES eax ebx ecx edx edi, destBuf:PTR BYTE, bitNum:DWORD, bitVal:DWORD
    mov     eax, bitNum
    dec     eax
    mov     ecx, eax
    shr     eax, 3
    and     ecx, 7
    mov     edi, destBuf
    add     edi, eax
    mov     edx, 7
    sub     edx, ecx
    mov     cl, dl
    mov     ebx, 1
    shl     ebx, cl             ; ebx = mask with the target bit set

    mov     eax, bitVal
    cmp     eax, 0
    je      SetBit_clear
    or      BYTE PTR [edi], bl
    jmp     SetBit_done
SetBit_clear:
    not     bl
    and     BYTE PTR [edi], bl
SetBit_done:
    ret
SetBit ENDP

; ============================================================================
; GenericPermute
;   destBuf[i] = srcBuf[ table[i] ]   for i = 1 .. tableLen
;   Caller must zero destBuf (ceil(tableLen/8) bytes) before calling.
;   No high-level control directives - plain CMP/JGE loop.
; ============================================================================
GenericPermute PROC USES eax ebx ecx edx esi edi, srcBuf:PTR BYTE, destBuf:PTR BYTE, table:PTR BYTE, tableLen:DWORD
    mov     ecx, 0                       ; loop index i (0-based)
GP_Loop:
    cmp     ecx, tableLen
    jge     GP_Done

    mov     esi, table
    add     esi, ecx
    movzx   eax, BYTE PTR [esi]          ; source bit position (1-based)

    push    ecx
    INVOKE  ExtractBit, srcBuf, eax
    pop     ecx
    mov     ebx, eax                     ; ebx = extracted bit value

    mov     eax, ecx
    inc     eax                          ; destination bit position (1-based)
    push    ecx
    INVOKE  SetBit, destBuf, eax, ebx
    pop     ecx

    inc     ecx
    jmp     GP_Loop
GP_Done:
    ret
GenericPermute ENDP

; ============================================================================
; InitialPermutation : 64-bit block -> 64-bit block, via IP_TABLE
; ============================================================================
InitialPermutation PROC USES eax, srcBlock:PTR BYTE, destBlock:PTR BYTE
    ; zero the 8-byte destination first
    mov     eax, destBlock
    mov     DWORD PTR [eax], 0
    mov     DWORD PTR [eax+4], 0
    INVOKE  GenericPermute, srcBlock, destBlock, ADDR IP_TABLE, 64
    ret
InitialPermutation ENDP

; ============================================================================
; FinalPermutation : 64-bit preoutput block -> 64-bit output block, via IPINV
; ============================================================================
FinalPermutation PROC USES eax, srcBlock:PTR BYTE, destBlock:PTR BYTE
    mov     eax, destBlock
    mov     DWORD PTR [eax], 0
    mov     DWORD PTR [eax+4], 0
    INVOKE  GenericPermute, srcBlock, destBlock, ADDR IPINV_TABLE, 64
    ret
FinalPermutation ENDP

; ============================================================================
; ExpandBlock : 32-bit half-block R -> 48-bit expanded block (6 bytes)
; ============================================================================
ExpandBlock PROC USES eax, R32:PTR BYTE, out48:PTR BYTE
    mov     eax, out48
    mov     DWORD PTR [eax], 0
    mov     BYTE PTR [eax+4], 0
    mov     BYTE PTR [eax+5], 0
    INVOKE  GenericPermute, R32, out48, ADDR E_TABLE, 48
    ret
ExpandBlock ENDP

; ============================================================================
; PermuteP : 32-bit S-box output -> 32-bit permuted output
; ============================================================================
PermuteP PROC USES eax, in32:PTR BYTE, out32:PTR BYTE
    mov     eax, out32
    mov     DWORD PTR [eax], 0
    INVOKE  GenericPermute, in32, out32, ADDR P_TABLE, 32
    ret
PermuteP ENDP

; ============================================================================
; XorBytes : dest[i] = a[i] XOR b[i], for i = 0 .. count-1
; ============================================================================
XorBytes PROC USES eax ebx ecx edx esi edi, a:PTR BYTE, b:PTR BYTE, dest:PTR BYTE, count:DWORD
    mov     esi, a
    mov     edi, b
    mov     edx, dest
    mov     ecx, 0
XB_Loop:
    cmp     ecx, count
    jge     XB_Done
    mov     al, BYTE PTR [esi+ecx]
    mov     bl, BYTE PTR [edi+ecx]
    xor     al, bl
    mov     BYTE PTR [edx+ecx], al
    inc     ecx
    jmp     XB_Loop
XB_Done:
    ret
XorBytes ENDP

; ============================================================================
; SBoxSubstitute
;   in48  : 6-byte (48-bit) buffer, already XORed with the round subkey
;   out32 : 4-byte (32-bit) buffer receiving the concatenated S-box output
;
;   For chunk i (0..7): bits [i*6+1 .. i*6+6] (1-based, MSB first) select
;   6 input bits b0 b1 b2 b3 b4 b5.
;     row = (b0 << 1) | b5
;     col = (b1<<3)|(b2<<2)|(b3<<1)|b4
;   The looked-up 4-bit value is written MSB-first into out32 bits
;   [i*4+1 .. i*4+4].
; ============================================================================
SBoxSubstitute PROC USES eax ebx ecx edx esi, in48:PTR BYTE, out32:PTR BYTE
    LOCAL   b0:DWORD, b1:DWORD, b2:DWORD, b3:DWORD, b4:DWORD, b5:DWORD
    LOCAL   row:DWORD, col:DWORD, sVal:DWORD, boxIdx:DWORD, baseBit:DWORD

    mov     eax, out32
    mov     DWORD PTR [eax], 0

    mov     boxIdx, 0
SB_Loop:
    cmp     boxIdx, 8
    jge     SB_Done

    ; baseBit = boxIdx*6 + 1   (1-based position of the first of the 6 bits)
    mov     eax, boxIdx
    mov     ecx, 6
    mul     ecx
    inc     eax
    mov     baseBit, eax

    ; extract the 6 bits b0..b5
    mov     eax, baseBit
    INVOKE  ExtractBit, in48, eax
    mov     b0, eax

    mov     eax, baseBit
    inc     eax
    INVOKE  ExtractBit, in48, eax
    mov     b1, eax

    mov     eax, baseBit
    add     eax, 2
    INVOKE  ExtractBit, in48, eax
    mov     b2, eax

    mov     eax, baseBit
    add     eax, 3
    INVOKE  ExtractBit, in48, eax
    mov     b3, eax

    mov     eax, baseBit
    add     eax, 4
    INVOKE  ExtractBit, in48, eax
    mov     b4, eax

    mov     eax, baseBit
    add     eax, 5
    INVOKE  ExtractBit, in48, eax
    mov     b5, eax

    ; row = (b0 << 1) | b5
    mov     eax, b0
    shl     eax, 1
    or      eax, b5
    mov     row, eax

    ; col = (b1<<3)|(b2<<2)|(b3<<1)|b4
    mov     eax, b1
    shl     eax, 3
    mov     ecx, b2
    shl     ecx, 2
    or      eax, ecx
    mov     ecx, b3
    shl     ecx, 1
    or      eax, ecx
    or      eax, b4
    mov     col, eax

    ; sVal = SBOX[ boxIdx*64 + row*16 + col ]
    mov     eax, row
    mov     ecx, 16
    mul     ecx
    add     eax, col
    mov     ecx, boxIdx
    push    eax
    mov     eax, 64
    mul     ecx
    mov     ecx, eax
    pop     eax
    add     eax, ecx
    mov     esi, OFFSET SBOX
    movzx   eax, BYTE PTR [esi+eax]
    mov     sVal, eax

    ; write the 4-bit result (MSB first) into out32 at position boxIdx*4+1..+4
    mov     eax, boxIdx
    mov     ecx, 4
    mul     ecx
    inc     eax                  ; eax = starting bit position (1-based)
    mov     baseBit, eax

    mov     eax, sVal
    shr     eax, 3
    and     eax, 1
    push    eax
    mov     eax, baseBit
    pop     ebx
    INVOKE  SetBit, out32, eax, ebx

    mov     eax, sVal
    shr     eax, 2
    and     eax, 1
    push    eax
    mov     eax, baseBit
    inc     eax
    pop     ebx
    INVOKE  SetBit, out32, eax, ebx

    mov     eax, sVal
    shr     eax, 1
    and     eax, 1
    push    eax
    mov     eax, baseBit
    add     eax, 2
    pop     ebx
    INVOKE  SetBit, out32, eax, ebx

    mov     eax, sVal
    and     eax, 1
    push    eax
    mov     eax, baseBit
    add     eax, 3
    pop     ebx
    INVOKE  SetBit, out32, eax, ebx

    inc     boxIdx
    jmp     SB_Loop
SB_Done:
    ret
SBoxSubstitute ENDP

; ============================================================================
; FeistelF : f(R,K) = P( S( E(R) XOR K ) )
;   Rin  : 4-byte (32-bit) half block
;   Kn   : 6-byte (48-bit) round subkey
;   Fout : 4-byte (32-bit) result
; ============================================================================
FeistelF PROC USES eax, Rin:PTR BYTE, Kn:PTR BYTE, Fout:PTR BYTE
    LOCAL   expanded[6]:BYTE, xored[6]:BYTE, sboxOut[4]:BYTE

    INVOKE  ExpandBlock, Rin, ADDR expanded
    INVOKE  XorBytes, ADDR expanded, Kn, ADDR xored, 6
    INVOKE  SBoxSubstitute, ADDR xored, ADDR sboxOut
    INVOKE  PermuteP, ADDR sboxOut, Fout
    ret
FeistelF ENDP

; ============================================================================
; DES_ProcessBlock
;   Runs IP, 16 Feistel rounds (subkey order depends on mode), swap, IP^-1.
;   inBlock/outBlock : 8-byte buffers.
;   subKeys          : 96-byte buffer, 16 subkeys of 6 bytes each, K1 first.
;   mode             : DES_ENCRYPT (0) uses K1..K16 forward,
;                       DES_DECRYPT (1) uses K16..K1 (reverse order).
; ============================================================================
DES_ProcessBlock PROC USES eax ebx ecx edx esi, inBlock:PTR BYTE, outBlock:PTR BYTE, subKeys:PTR BYTE, mode:DWORD
    LOCAL   permuted[8]:BYTE          ; IP(input)
    LOCAL   Lcur[4]:BYTE, Rcur[4]:BYTE
    LOCAL   Lnext[4]:BYTE, Rnext[4]:BYTE
    LOCAL   fResult[4]:BYTE
    LOCAL   preOutput[8]:BYTE
    LOCAL   roundNum:DWORD, keyOffset:DWORD

    INVOKE  InitialPermutation, inBlock, ADDR permuted

    ; L0 = permuted[0..3], R0 = permuted[4..7]
    lea     esi, permuted
    mov     eax, DWORD PTR [esi]
    mov     DWORD PTR Lcur, eax
    mov     eax, DWORD PTR [esi+4]
    mov     DWORD PTR Rcur, eax

    mov     roundNum, 1
DP_RoundLoop:
    cmp     roundNum, ROUND_COUNT
    jg      DP_RoundsDone

    ; ---- determine which subkey to use for this round ----
    cmp     mode, DES_ENCRYPT
    jne     DP_ReverseKey
    mov     eax, roundNum
    dec     eax
    jmp     DP_KeyOffsetComputed
DP_ReverseKey:
    mov     eax, ROUND_COUNT
    sub     eax, roundNum        ; roundNum=1 -> index 15 (K16), ... roundNum=16 -> index 0 (K1)
DP_KeyOffsetComputed:
    mov     ecx, 6
    mul     ecx
    mov     keyOffset, eax

    mov     esi, subKeys
    add     esi, keyOffset       ; esi -> Kn for this round

    ; fResult = f(Rcur, Kn)
    INVOKE  FeistelF, ADDR Rcur, esi, ADDR fResult

    ; Lnext = Rcur
    mov     eax, DWORD PTR Rcur
    mov     DWORD PTR Lnext, eax

    ; Rnext = Lcur XOR fResult
    INVOKE  XorBytes, ADDR Lcur, ADDR fResult, ADDR Rnext, 4

    ; Lcur = Lnext ; Rcur = Rnext
    mov     eax, DWORD PTR Lnext
    mov     DWORD PTR Lcur, eax
    mov     eax, DWORD PTR Rnext
    mov     DWORD PTR Rcur, eax

    inc     roundNum
    jmp     DP_RoundLoop
DP_RoundsDone:

    ; preoutput = R16 || L16  (note the swap relative to the last L/R pair)
    lea     esi, preOutput
    mov     eax, DWORD PTR Rcur
    mov     DWORD PTR [esi], eax
    mov     eax, DWORD PTR Lcur
    mov     DWORD PTR [esi+4], eax

    INVOKE  FinalPermutation, ADDR preOutput, outBlock
    ret
DES_ProcessBlock ENDP

; ============================================================================
; PKCS7_AddPadding
;   Pads buffer (already containing dataLen bytes of plaintext, with room
;   for up to 8 more bytes) to a multiple of 8. Always adds 1-8 padding
;   bytes (even if dataLen is already a multiple of 8), each byte equal to
;   the pad length. Returns the new total length in EAX.
; ============================================================================
PKCS7_AddPadding PROC USES ebx ecx edx edi, buffer:PTR BYTE, dataLen:DWORD
    mov     eax, dataLen
    xor     edx, edx
    mov     ecx, BLOCK_SIZE
    div     ecx                  ; eax = dataLen/8, edx = dataLen mod 8

    mov     ecx, BLOCK_SIZE
    sub     ecx, edx             ; ecx = pad length (1..8)

    mov     edi, buffer
    add     edi, dataLen         ; point past existing data

    mov     ebx, 0               ; bytes written so far
PAD_Loop:
    cmp     ebx, ecx
    jge     PAD_Done
    mov     BYTE PTR [edi+ebx], cl
    inc     ebx
    jmp     PAD_Loop
PAD_Done:
    mov     eax, dataLen
    add     eax, ecx             ; new total length
    ret
PKCS7_AddPadding ENDP

; ============================================================================
; PKCS7_RemovePadding
;   Reads the padding value from the last byte of buffer (totalLen bytes)
;   and returns the unpadded data length in EAX. If the pad value is not
;   in the valid range 1..8 (corrupt ciphertext/wrong key), returns -1.
; ============================================================================
PKCS7_RemovePadding PROC USES ebx esi, buffer:PTR BYTE, totalLen:DWORD
    mov     esi, buffer
    mov     eax, totalLen
    dec     eax
    movzx   ebx, BYTE PTR [esi+eax]   ; ebx = pad value from last byte

    cmp     ebx, 1
    jl      PRP_Invalid
    cmp     ebx, BLOCK_SIZE
    jg      PRP_Invalid

    mov     eax, totalLen
    sub     eax, ebx
    ret
PRP_Invalid:
    mov     eax, -1
    ret
PKCS7_RemovePadding ENDP

; ============================================================================
; DES_ECB_Encrypt
;   buffer  : plaintext in, ciphertext out (in place). Must have room for
;             up to 8 extra padding bytes beyond dataLen.
;   dataLen : length of plaintext before padding.
;   subKeys : 96-byte subkey schedule (K1..K16).
;   outLen  : receives the total ciphertext length (multiple of 8) written
;             back through the pointer.
; ============================================================================
DES_ECB_Encrypt PROC USES eax ebx ecx edx esi edi, buffer:PTR BYTE, dataLen:DWORD, subKeys:PTR BYTE, outLen:PTR DWORD
    LOCAL   paddedLen:DWORD, blockOut[8]:BYTE

    INVOKE  PKCS7_AddPadding, buffer, dataLen
    mov     paddedLen, eax

    mov     edi, outLen
    mov     eax, paddedLen
    mov     DWORD PTR [edi], eax

    mov     esi, buffer
    mov     ecx, 0                       ; byte offset of current block
EE_Loop:
    cmp     ecx, paddedLen
    jge     EE_Done

    mov     edx, esi
    add     edx, ecx

    push    ecx
    INVOKE  DES_ProcessBlock, edx, ADDR blockOut, subKeys, DES_ENCRYPT
    pop     ecx
    ; copy blockOut back over the plaintext block in place
    push    ecx
    mov     ebx, esi
    add     ebx, ecx
    mov     eax, DWORD PTR blockOut
    mov     DWORD PTR [ebx], eax
    mov     eax, DWORD PTR (blockOut+4)
    mov     DWORD PTR [ebx+4], eax
    pop     ecx

    add     ecx, BLOCK_SIZE
    jmp     EE_Loop
EE_Done:
    ret
DES_ECB_Encrypt ENDP

; ===========================================================================
; DES_ECB_Decrypt
;   buffer  : ciphertext in, plaintext out (in place, still padded).
;   dataLen : ciphertext length (must be a multiple of 8).
;   subKeys : 96-byte subkey schedule (K1..K16).
;   outLen  : receives the final plaintext length AFTER PKCS#7 unpadding
;             (or -1 if the padding was invalid).
; ============================================================================
DES_ECB_Decrypt PROC USES eax ebx ecx edx esi edi, buffer:PTR BYTE, dataLen:DWORD, subKeys:PTR BYTE, outLen:PTR DWORD
    LOCAL   blockOut[8]:BYTE

    mov     esi, buffer
    mov     ecx, 0
ED_Loop:
    cmp     ecx, dataLen
    jge     ED_Done

   mov     edx, esi
   add     edx, ecx

   push    ecx
   INVOKE  DES_ProcessBlock, edx, ADDR blockOut, subKeys, DES_DECRYPT
   pop     ecx

    push    ecx
    mov     ebx, esi
    add     ebx, ecx
    mov     eax, DWORD PTR blockOut
    mov     DWORD PTR [ebx], eax
    mov     eax, DWORD PTR (blockOut+4)
    mov     DWORD PTR [ebx+4], eax
    pop     ecx

    add     ecx, BLOCK_SIZE
    jmp     ED_Loop
ED_Done:
    INVOKE  PKCS7_RemovePadding, buffer, dataLen
    mov     edi, outLen
    mov     DWORD PTR [edi], eax
    ret
DES_ECB_Decrypt ENDP

END
