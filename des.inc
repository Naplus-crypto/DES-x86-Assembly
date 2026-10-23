; ----------------------------------------------------------------------------
;      Module B
; ----------------------------------------------------------------------------
; ต้องตรงกับ Module_B.asm:270 (ใช้ [ebp+8]=keyHi, [ebp+12]=keyLo, [ebp+16]=pSubkeys, ret 12)
des_key_schedule    PROTO, keyHi:DWORD, keyLo:DWORD, pSubkeys:PTR BYTE

; ----------------------------------------------------------------------------
;      Module C
; ----------------------------------------------------------------------------
; Procedure prototypes (call these from Module A / your shell)
InitialPermutation   PROTO, srcBlock:PTR BYTE, destBlock:PTR BYTE
FinalPermutation     PROTO, srcBlock:PTR BYTE, destBlock:PTR BYTE
FeistelF             PROTO, Rin:PTR BYTE, Kn:PTR BYTE, Fout:PTR BYTE
DES_ProcessBlock     PROTO, inBlock:PTR BYTE, outBlock:PTR BYTE, subKeys:PTR BYTE, mode:DWORD
DES_ECB_Encrypt      PROTO, buffer:PTR BYTE, dataLen:DWORD, subKeys:PTR BYTE, outLen:PTR DWORD
DES_ECB_Decrypt      PROTO, buffer:PTR BYTE, dataLen:DWORD, subKeys:PTR BYTE, outLen:PTR DWORD
PKCS7_AddPadding     PROTO, buffer:PTR BYTE, dataLen:DWORD
PKCS7_RemovePadding  PROTO, buffer:PTR BYTE, totalLen:DWORD

; Internal helpers (still exposed in case Module A/D want to reuse them)
ExtractBit           PROTO, srcBuf:PTR BYTE, bitNum:DWORD
SetBit               PROTO, destBuf:PTR BYTE, bitNum:DWORD, bitVal:DWORD
GenericPermute       PROTO, srcBuf:PTR BYTE, destBuf:PTR BYTE, table:PTR BYTE, tableLen:DWORD
ExpandBlock          PROTO, R32:PTR BYTE, out48:PTR BYTE
PermuteP             PROTO, in32:PTR BYTE, out32:PTR BYTE
SBoxSubstitute       PROTO, in48:PTR BYTE, out32:PTR BYTE
XorBytes             PROTO, a:PTR BYTE, b:PTR BYTE, dest:PTR BYTE, count:DWORD

; Encrypt/Decrypt mode constants
DES_ENCRYPT   EQU 0
DES_DECRYPT   EQU 1
BLOCK_SIZE    EQU 8
ROUND_COUNT   EQU 16

; ----------------------------------------------------------------------------
;      Module D (STDCALL cleanup inside the module, same style as Module B)
; ----------------------------------------------------------------------------
; ทั้งสองตัวใช้ [ebp+8]=dataLen, [ebp+12]=buffer และ ret 8
DisplayHexDump       PROTO, dataLen:DWORD, buffer:PTR BYTE
ComputeBufferStats   PROTO, dataLen:DWORD, buffer:PTR BYTE
