$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$readmePath = Join-Path $repoRoot "README.md"
$vsDevCmd = $null

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

function Invoke-InRepoCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $fullCommand = if ($vsDevCmd -and (Test-Path $vsDevCmd)) {
        "`"$vsDevCmd`" -arch=x64 -host_arch=x64 && cd /d `"$repoRoot`" && $Command"
    } else {
        "cd /d `"$repoRoot`" && $Command"
    }

    $output = cmd /c "$fullCommand 2>&1"
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed (exit=$LASTEXITCODE): $Command`n$output"
    }
    return ($output | Out-String)
}

$vsDevCmd = Resolve-VsDevCmd

if (-not (Test-Path $readmePath)) {
    throw "README.md not found at $readmePath"
}

$readmeText = Get-Content $readmePath -Raw

$rustMatch = [regex]::Match($readmeText, "(?m)^- Rust tests: ([0-9]+)\r?$")
$juliaMatch = [regex]::Match($readmeText, "(?m)^- Julia tests: ([0-9]+)\r?$")
$zigMatch = [regex]::Match($readmeText, "(?m)^- Zig tests: ([0-9]+)\r?$")
$totalMatch = [regex]::Match($readmeText, "(?m)^- Total tests: ([0-9]+)\r?$")

if (-not ($rustMatch.Success -and $juliaMatch.Success -and $zigMatch.Success -and $totalMatch.Success)) {
    throw "README test counters not found or malformed."
}

$readmeRust = [int]$rustMatch.Groups[1].Value
$readmeJulia = [int]$juliaMatch.Groups[1].Value
$readmeZig = [int]$zigMatch.Groups[1].Value
$readmeTotal = [int]$totalMatch.Groups[1].Value

if (-not [regex]::IsMatch($readmeText, "(?m)^[\s]*-[\s]*BLAKE3 \+ SHAKE256")) {
    throw "README tech stack hash line is missing or outdated."
}

if ([regex]::IsMatch($readmeText, "(?m)^[\s]*-[\s]*BLAKE3 \+ SHA3-256")) {
    throw "README still contains deprecated runtime tech stack line with SHA3-256."
}

$actualRust = [int]((Get-ChildItem (Join-Path $repoRoot "src") -Recurse -Filter *.rs | Select-String -Pattern '#\[tokio::test\]|#\[test\]' | Measure-Object).Count)
$actualZig = [int]((Get-ChildItem (Join-Path $repoRoot "tools\zig\src") -Recurse -Filter *.zig | Select-String -Pattern '^test "' | Measure-Object).Count)

if (-not (Get-Command julia -ErrorAction SilentlyContinue)) {
    throw "julia command not found; cannot validate Julia test total."
}

$juliaOutputText = Invoke-InRepoCapture -Command "julia --project=./julia julia/test/runtests.jl"
$juliaTotalMatch = [regex]::Match($juliaOutputText, "(?m)^PLCA score and risk_bps\s+\|\s+[0-9]+\s+([0-9]+)")
if (-not $juliaTotalMatch.Success) {
    Write-Host $juliaOutputText
    throw "Could not parse Julia test total from julia/test/runtests.jl output."
}
$actualJulia = [int]$juliaTotalMatch.Groups[1].Value

$actualTotal = $actualRust + $actualJulia + $actualZig

Write-Host "README counters: rust=$readmeRust julia=$readmeJulia zig=$readmeZig total=$readmeTotal"
Write-Host "Actual counters: rust=$actualRust julia=$actualJulia zig=$actualZig total=$actualTotal"

if ($readmeRust -ne $actualRust) {
    throw "Mismatch: README Rust tests=$readmeRust but actual=$actualRust"
}
if ($readmeJulia -ne $actualJulia) {
    throw "Mismatch: README Julia tests=$readmeJulia but actual=$actualJulia"
}
if ($readmeZig -ne $actualZig) {
    throw "Mismatch: README Zig tests=$readmeZig but actual=$actualZig"
}
if ($readmeTotal -ne $actualTotal) {
    throw "Mismatch: README Total tests=$readmeTotal but actual=$actualTotal"
}

Write-Host "README consistency check passed."
