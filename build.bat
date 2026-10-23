@echo off
REM ==========================================================================
REM  DES x86 Assembly - MASM build script
REM  Sets up the MSVC x86 toolchain by itself, so it can be double-clicked
REM  or run from any shell without first opening a "Developer Command Prompt".
REM
REM  Usage:
REM    build.bat              assemble + link, then run des.exe
REM    build.bat buildonly     assemble + link only
REM ==========================================================================
setlocal EnableExtensions EnableDelayedExpansion
cls
pushd "%~dp0" || exit /b 1
title DES x86 Assembly - MASM Build

set "SRC_A=Module_A.asm"
set "SRC_B=Module_B.asm"
set "SRC_C=Module_C.asm"
set "SRC_D=Module_D.asm"
set "OBJ_A=Module_A.obj"
set "OBJ_B=Module_B.obj"
set "OBJ_C=Module_C.obj"
set "OBJ_D=Module_D.obj"
set "IRVINE=Irvine"
set "EXE=des.exe"

echo ============================================
echo   Assembling and Linking MASM Project...
echo ============================================
echo.

REM --------------------------------------------------------------------------
REM  [1/4] Make sure ml.exe and link.exe are reachable
REM --------------------------------------------------------------------------
call :setup_toolchain
if errorlevel 1 goto NO_TOOLCHAIN

where ml.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] ml.exe is still not on PATH after toolchain setup.
    goto NO_TOOLCHAIN
)
where link.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] link.exe is still not on PATH after toolchain setup.
    goto NO_TOOLCHAIN
)

if not exist "%IRVINE%\Irvine32.inc" (
    echo [ERROR] Cannot find "%IRVINE%\Irvine32.inc".
    goto NO_TOOLCHAIN
)
if not exist "%IRVINE%\Irvine32.lib" (
    echo [ERROR] Cannot find "%IRVINE%\Irvine32.lib".
    goto NO_TOOLCHAIN
)

REM --------------------------------------------------------------------------
REM  [2/4] Remove previous build output
REM --------------------------------------------------------------------------
echo [2/4] Cleaning previous build output...
if exist "%EXE%"   del /q "%EXE%"
if exist "des.pdb" del /q "des.pdb"
del /q "%OBJ_A%" "%OBJ_B%" "%OBJ_C%" "%OBJ_D%" 2>nul
del /q "Module_A.lst" "Module_B.lst" "Module_C.lst" "Module_D.lst" 2>nul

REM --------------------------------------------------------------------------
REM  [3/4] Assemble  (/I pulls the .inc files from the local Irvine folder)
REM --------------------------------------------------------------------------
echo [3/4] Assembling source files...
ml /nologo /Sn /Sa /Zi /c /coff /Fl /I "%IRVINE%" "%SRC_A%" "%SRC_B%" "%SRC_C%" "%SRC_D%"
if errorlevel 1 goto BUILD_FAIL

REM --------------------------------------------------------------------------
REM  [4/4] Link  (/LIBPATH pulls Irvine32.lib from the local Irvine folder)
REM --------------------------------------------------------------------------
echo [4/4] Linking object files...
link /nologo /subsystem:console /debug /opt:noref /opt:noicf /LIBPATH:"%IRVINE%" /out:"%EXE%" "%OBJ_A%" "%OBJ_B%" "%OBJ_C%" "%OBJ_D%" "%IRVINE%\Irvine32.lib"
if errorlevel 1 goto LINK_FAIL

echo.
echo ============================================
echo   BUILD SUCCEEDED
echo ============================================
echo.

if /i "%~1"=="buildonly" goto END

echo Running %EXE%...
echo.
"%EXE%"
goto END

REM --------------------------------------------------------------------------
REM  Failure handlers
REM --------------------------------------------------------------------------
:NO_TOOLCHAIN
echo.
echo [ERROR] No usable MSVC x86 build tools were found.
echo         Install "Desktop development with C++" from the Visual Studio
echo         Installer, or run build.bat from a Developer Command Prompt.
set "RC=1"
goto FINISH

:BUILD_FAIL
echo.
echo [ERROR] Assembly failed. See the errors above and check the .lst files.
set "RC=2"
goto FINISH

:LINK_FAIL
echo.
echo [ERROR] Linking failed. See the errors above.
set "RC=3"
goto FINISH

:END
set "RC=0"

:FINISH
echo.
popd
endlocal & exit /b %RC%

REM ==========================================================================
REM  Toolchain discovery
REM  Preferred path: VsDevCmd.bat (Microsoft keeps it in sync with the IDE).
REM  Fallback: locate the MSVC + Windows SDK directories and build the
REM             INCLUDE / LIB / PATH entries by hand.
REM ==========================================================================
:setup_toolchain
set "VSPATH="
set "VSDEVCMD="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do (
        if not defined VSPATH set "VSPATH=%%i"
    )
)

if defined VSPATH (
    if exist "%VSPATH%\Common7\Tools\VsDevCmd.bat" set "VSDEVCMD=%VSPATH%\Common7\Tools\VsDevCmd.bat"
)

if defined VSDEVCMD (
    echo [env] Using VsDevCmd.bat -arch=x86 -host_arch=x64
    call "%VSDEVCMD%" -arch=x86 -host_arch=x64 -no_logo >nul 2>&1
    exit /b 0
)

echo [env] VsDevCmd.bat not available - locating MSVC and Windows SDK manually...
call :manual_env
exit /b %errorlevel%

:manual_env
set "MSVCDIR="
for %%r in ("%ProgramFiles(x86)%\Microsoft Visual Studio" "%ProgramFiles%\Microsoft Visual Studio") do (
    if exist "%%~r" (
        for /f "delims=" %%d in ('dir /s /b /ad /o-n "%%~r\*\VC\Tools\MSVC" 2^>nul') do (
            if not defined MSVCDIR if exist "%%d\bin\Hostx64\x86\ml.exe" set "MSVCDIR=%%d"
        )
    )
)
if not defined MSVCDIR exit /b 1

set "SDKBASE=%ProgramFiles(x86)%\Windows Kits\10"
if not exist "%SDKBASE%\Include" set "SDKBASE=%ProgramFiles%\Windows Kits\10"
if not exist "%SDKBASE%\Include" exit /b 1

set "SDKVER="
for /f "delims=" %%v in ('dir /b /ad /o-n "%SDKBASE%\Include" 2^>nul') do (
    if not defined SDKVER (
        if exist "%SDKBASE%\Include\%%v\um\windows.h" set "SDKVER=%%v"
    )
)
if not defined SDKVER exit /b 1

echo [env] MSVC  : %MSVCDIR%
echo [env] SDK   : %SDKBASE%\%SDKVER%
set "PATH=%MSVCDIR%\bin\Hostx64\x86;%SDKBASE%\bin\%SDKVER%\x86;%PATH%"
set "INCLUDE=%MSVCDIR%\include;%SDKBASE%\Include\%SDKVER%\ucrt;%SDKBASE%\Include\%SDKVER%\um;%SDKBASE%\Include\%SDKVER%\shared"
set "LIB=%MSVCDIR%\lib\x86;%SDKBASE%\Lib\%SDKVER%\ucrt\x86;%SDKBASE%\Lib\%SDKVER%\um\x86"
exit /b 0
