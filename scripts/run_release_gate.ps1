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
    } else {
        Push-Location $repoRoot
        try {
            Invoke-Expression $Command
        } finally {
            Pop-Location
        }
    }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "run_release_gate(ps1): cargo not found in PATH. Install Rust toolchain first."
}

if (-not (Get-Command julia -ErrorAction SilentlyContinue)) {
    throw "run_release_gate(ps1): julia not found in PATH. Install Julia first."
}

if (-not $vsDevCmd) {
    Write-Host "run_release_gate(ps1): VsDevCmd not found (continuing with current shell environment)."
}

if (-not (Get-Command bash -ErrorAction SilentlyContinue)) {
    throw "run_release_gate(ps1): bash not found in PATH. Install Git Bash (or WSL) to run shell validation scripts."
}

Write-Host "run_release_gate(ps1): cargo fmt --check"
Invoke-InRepo -Command "cargo fmt --check"

Write-Host "run_release_gate(ps1): cargo clippy --all-targets --all-features -- -D warnings"
Invoke-InRepo -Command "cargo clippy --all-targets --all-features -- -D warnings"

Write-Host "run_release_gate(ps1): scripts/check_readme_consistency.ps1"
& (Join-Path $repoRoot "scripts\check_readme_consistency.ps1")

Write-Host "run_release_gate(ps1): bash scripts/check_supply_chain_surface.sh"
Invoke-InRepo -Command "bash scripts/check_supply_chain_surface.sh"

Write-Host "run_release_gate(ps1): cargo deny check"
Invoke-InRepo -Command "cargo deny check"

Write-Host "run_release_gate(ps1): scripts/run_trust_core_checks.ps1"
& (Join-Path $repoRoot "scripts\run_trust_core_checks.ps1")

$zig = Get-Command zig -ErrorAction SilentlyContinue
if ($null -ne $zig) {
    Write-Host "run_release_gate(ps1): cd tools/zig; zig build run -- verify ../../fixtures/audit_sample.jsonl"
    Push-Location (Join-Path $repoRoot "tools\zig")
    try {
        zig build run -- verify ../../fixtures/audit_sample.jsonl
        zig build run -- verify --require-chain ../../fixtures/audit_chain_sample.jsonl
    } finally {
        Pop-Location
    }
} elseif ($env:NEXO_ALLOW_MISSING_ZIG -eq "1") {
    Write-Host "run_release_gate(ps1): zig not found in PATH, skipping offline verify steps (NEXO_ALLOW_MISSING_ZIG=1)"
} else {
    throw "run_release_gate(ps1): zig not found in PATH. Install zig or set NEXO_ALLOW_MISSING_ZIG=1 for local-only skip."
}

Write-Host "run_release_gate(ps1): ok"
