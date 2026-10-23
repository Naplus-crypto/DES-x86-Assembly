================================================================================
01476105 Computer Organization and Assembly Language
Computer Engineering and Cyber Security, KMITL
Coursework Project: Command-Line Shell & File Encryption Engine (Classical DES)
================================================================================

1. สมาชิกในกลุ่มและความรับผิดชอบ (Project Team & Contributions)
--------------------------------------------------------------------------------
1. นาย ณัฐวัฒน์ กิตตินวเวช      รหัสนักศึกษา: 68010372
   ความรับผิดชอบ: Module A - Shell Core & FSM Command Parser
   - พัฒนา Main REPL Loop รับคำสั่งจาก Console
   - พัฒนา FSM Tokenizer และวิเคราะห์คำสั่ง (KEYGEN, ENCRYPT, DECRYPT, DUMP, STATS, CLEAR, EXIT)
   - จัดการ File I/O และตรวจสอบความถูกต้องของรูปแบบคำสั่งและ Key (16-digit hex)

2. นาย สุรเจษฐ์ ตลาดธานี       รหัสนักศึกษา: 68011174
   ความรับผิดชอบ: Module B - DES Key Schedule Generator
   - พัฒนาฟังก์ชัน Permuted Choice 1 (PC-1) และ Permuted Choice 2 (PC-2)
   - คำนวณ Left Circular Shifts (ROL 1-bit / 2-bit) สำหรับ C_i และ D_i ทั้ง 16 รอบ
   - สร้าง Round Subkeys ขนาด 48 bits (K1 ถึง K16) ตามมาตรฐาน FIPS 46-3

3. นาย ปฏิภาณ ประทุมวัน        รหัสนักศึกษา: 68010627
   ความรับผิดชอบ: Module C - DES 16-Round Feistel Core Engine
   - พัฒนา Initial Permutation (IP) และ Inverse Initial Permutation (IP^-1)
   - พัฒนา Feistel Function f(R, K): Expansion (E), Subkey XOR, 2D S-Box Lookups (S1-S8), Permutation (P)
   - พัฒนา Electronic Codebook (ECB) Mode 16 Feistel Rounds และ PKCS#7 Padding/Unpadding

4. นาย ประกฤต ขวัญพัทลุง       รหัสนักศึกษา: 68010653
   ความรับผิดชอบ: Module D - Memory Dumper & Buffer Analytics
   - พัฒนา DisplayHexDump: แสดง Offset Address, Hex Dump 16 bytes/แถว และคอลัมน์ ASCII
   - พัฒนา ComputeBufferStats: คำนวณ Histogram 256 Bins, คำนวณ Shannon Entropy และ Diffusion Verdict
   - จัดอันดับ Top 5 Byte Occurrences พร้อม Tie-break ตามลำดับการปรากฏจริงในไฟล์

--------------------------------------------------------------------------------
2. ข้อกำหนดทางเทคนิคและการปฏิบัติตามเกณฑ์ (Technical Compliance)
--------------------------------------------------------------------------------
- สถาปัตยกรรม: x86 assembly (32-bit Protected Mode, MASM Standard, .386)
- กฎ 2.a (Low-level Control Flow): ห้ามใช้ directive ระดับสูง (.IF, .WHILE, .REPEAT)
  ในลูปคำนวณและ parser -> โค้ดทั้งหมดใช้คำสั่ง CMP, TEST, Jxx, LOOP เท่านั้น
- กฎ 2.b (Calling Convention): ทุก procedure ใช้ Standard Stack Frame Pointer
  (push ebp / mov ebp, esp / pop ebp) บันทึก registers ของ caller และคืนค่าผ่าน EAX
- กฎ 2.c (Zero External Library): พัฒนาอัลกอริทึมการเข้ารหัสลับ DES เองทั้งหมด 100%
- กฎ 2.d (File I/O): ใช้ Irvine32 procedures (OpenInputFile, ReadFromFile, CreateOutputFile,
  WriteToFile, CloseFile) 

--------------------------------------------------------------------------------
3. คำสั่งที่รองรับ (Supported Commands)
--------------------------------------------------------------------------------
1) KEYGEN <key>
   คำนวณและแสดงผล Key Schedule ทั้ง 16 รอบ (K1 ถึง K16) จาก Key ขนาด 64 bits (16-digit hex)
2) ENCRYPT <file> <key>
   เข้ารหัสลับไฟล์ plaintext ในโหมด ECB พร้อมเติม PKCS#7 padding ได้ไฟล์ผลลัพธ์ .enc
3) DECRYPT <file> <key>
   ถอดรหัสลับไฟล์ ciphertext ในโหมด ECB พร้อมตัด PKCS#7 padding ได้ไฟล์ผลลัพธ์ .dec
4) DUMP <file>
   แสดงผลข้อมูลในไฟล์ในรูปแบบ Hex 16 ไบต์ต่อบรรทัด พร้อมตำแหน่ง Offset และ ASCII
5) STATS <file>
   แสดงผลขนาดไฟล์, ค่า Shannon Entropy, ผลการตรวจสอบ Uniformity และ Top 5 Byte Occurrences
6) CLEAR
   ล้างหน้าจอ Console
7) EXIT
   ออกจากโปรแกรม

--------------------------------------------------------------------------------
4. วิธีการบิลด์และรันโปรแกรม (Build & Execution)
--------------------------------------------------------------------------------
วิธีที่ 1 (อัตโนมัติ):
   รัน build.bat ในหน้าต่าง Command Prompt หรือดับเบิลคลิกไฟล์ build.bat
   (สคริปต์จะค้นหา MSVC x86 toolchain และ Windows SDK ให้อัตโนมัติ)

วิธีที่ 2 (ผ่าน Developer Command Prompt):
   ml /nologo /Sn /Sa /Zi /c /coff /Fl /I "Irvine" Module_A.asm Module_B.asm Module_C.asm Module_D.asm
   link /SUBSYSTEM:CONSOLE /LIBPATH:"Irvine" /OPT:NOREF /OPT:NOICF /DEBUG /NOLOGO /OUT:des.exe Module_A.obj Module_B.obj Module_C.obj Module_D.obj Irvine32.lib
   des.exe
================================================================================
