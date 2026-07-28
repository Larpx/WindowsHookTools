# 编译 HookMonitor Native DLL（薄包装）

# 调用 src/HookMonitor.Native/build.bat
# 建议在 “x64 Native Tools Command Prompt for VS 2022” 中运行，或确保 cl.exe 在 PATH 中。
#
# 用法：
#   .\scripts\build-native.ps1
#   .\scripts\build-native.ps1 -MsBuild

param(
    [switch]$MsBuild
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$nativeDir = Join-Path $repoRoot "src\HookMonitor.Native"
$buildBat = Join-Path $nativeDir "build.bat"

if (-not (Test-Path $buildBat)) {
    throw "找不到构建脚本: $buildBat"
}

Push-Location $nativeDir
try {
    if ($MsBuild) {
        & cmd.exe /c "build.bat msbuild"
    }
    else {
        & cmd.exe /c "build.bat"
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Native DLL 编译失败，退出码: $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
