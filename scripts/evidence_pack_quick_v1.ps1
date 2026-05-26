param(
    [string]$ApiUrl = "http://127.0.0.1:3000"
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "evidence_pack_quick_v1: missing required command: $Name"
    }
}

Require-Command bash

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

$env:API_URL = $ApiUrl

Write-Host "evidence_pack_quick_v1: running from $repoRoot"
bash scripts/evidence_pack_quick_v1.sh
