$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$vsDevCmd = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"

function Invoke-InRepo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    if (Test-Path $vsDevCmd) {
        cmd /c "`"$vsDevCmd`" -arch=x64 -host_arch=x64 && cd /d `"$repoRoot`" && $Command"
    } else {
        Push-Location $repoRoot
        try {
            Invoke-Expression $Command
        } finally {
            Pop-Location
        }
    }
}

Write-Host "run_trust_core_checks(ps1): cargo test -q"
Invoke-InRepo -Command "cargo test -q"

Write-Host "run_trust_core_checks(ps1): cargo test --features network -q"
Invoke-InRepo -Command "cargo test --features network -q"

Write-Host "run_trust_core_checks(ps1): julia --project=./julia julia/test/runtests.jl"
Invoke-InRepo -Command "julia --project=./julia julia/test/runtests.jl"

$zig = Get-Command zig -ErrorAction SilentlyContinue
if ($null -ne $zig) {
    Write-Host "run_trust_core_checks(ps1): cd tools/zig; zig build test"
    Push-Location (Join-Path $repoRoot "tools\zig")
    try {
        zig build test
    } finally {
        Pop-Location
    }
} elseif ($env:NEXO_ALLOW_MISSING_ZIG -eq "1") {
    Write-Host "run_trust_core_checks(ps1): zig not found in PATH, skipping zig build test (NEXO_ALLOW_MISSING_ZIG=1)"
} else {
    throw "run_trust_core_checks(ps1): zig not found in PATH. Install zig or set NEXO_ALLOW_MISSING_ZIG=1 to skip locally."
}

Write-Host "run_trust_core_checks(ps1): ok"
