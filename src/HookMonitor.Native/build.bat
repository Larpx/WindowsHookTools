@echo off
REM HookMonitorAgent 构建脚本
REM 使用 Visual Studio 的 MSBuild 或 cl.exe 编译
REM
REM 用法：
REM   1. 打开"x64 Native Tools Command Prompt for VS 2022"
REM   2. 运行 build.bat
REM
REM 或者直接使用 MSBuild：
REM   build.bat msbuild

setlocal

set DLL_NAME=HookMonitorAgent
set SOURCE=HookMonitorAgent.c
set OUTPUT_DIR=..\..\artifacts\bin

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

if "%1"=="msbuild" goto :msbuild

REM 使用 cl.exe 直接编译
echo 正在编译 %DLL_NAME%.dll ...

cl.exe /nologo /O2 /LD /W4 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_USRDLL" ^
    /D "HOOKMONITOR_EXPORTS" ^
    /Fe"%OUTPUT_DIR%\%DLL_NAME%.dll" ^
    /Fo"%OUTPUT_DIR%\" ^
    /Fd"%OUTPUT_DIR%\" ^
    %SOURCE% ^
    kernel32.lib user32.lib gdi32.lib ntdll.lib advapi32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo 编译成功: %OUTPUT_DIR%\%DLL_NAME%.dll
) else (
    echo.
    echo 编译失败！
)

goto :end

:msbuild
REM 使用 MSBuild 编译（需要 .vcxproj 文件）
echo 正在使用 MSBuild 编译...
msbuild /p:Configuration=Release /p:Platform=x64
goto :end

:end
endlocal
