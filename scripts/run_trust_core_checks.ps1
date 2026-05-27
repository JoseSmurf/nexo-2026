$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Resolve-VsDevCmd {
    if ($env:VSDEVCMD_BAT -and (Test-Path $env:VSDEVCMD_BAT)) {
        return $env:VSDEVCMD_BAT
    }

    $candidates = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

$vsDevCmd = Resolve-VsDevCmd

function Invoke-InRepo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    if ($vsDevCmd -and (Test-Path $vsDevCmd)) {
        cmd /c "`"$vsDevCmd`" -arch=x64 -host_arch=x64 && cd /d `"$repoRoot`" && $Command"
        if ($LASTEXITCODE -ne 0) {
            throw "run_trust_core_checks(ps1): command failed (exit=$LASTEXITCODE): $Command"
        }
    } else {
        Push-Location $repoRoot
        try {
            Invoke-Expression $Command
            if ($LASTEXITCODE -ne 0) {
                throw "run_trust_core_checks(ps1): command failed (exit=$LASTEXITCODE): $Command"
            }
        } finally {
            Pop-Location
        }
    }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "run_trust_core_checks(ps1): cargo not found in PATH. Install Rust toolchain first."
}

if (-not (Get-Command julia -ErrorAction SilentlyContinue)) {
    throw "run_trust_core_checks(ps1): julia not found in PATH. Install Julia first."
}

if (-not $vsDevCmd) {
    Write-Host "run_trust_core_checks(ps1): VsDevCmd not found (continuing with current shell environment)."
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
