param(
    [switch]$PlcaOnly,
    [string]$JuliaProject = "./julia",
    [string]$JuliaEntry = "julia/test/runtests.jl"
)

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

function Import-VsDevEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VsDevCmdPath
    )

    $escapedPath = $VsDevCmdPath.Replace('"', '\"')
    $dump = cmd /c """$escapedPath"" -arch=x64 -host_arch=x64 >nul && set"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to initialize Visual Studio developer environment."
    }

    foreach ($line in $dump) {
        $idx = $line.IndexOf("=")
        if ($idx -le 0) {
            continue
        }
        $name = $line.Substring(0, $idx)
        $value = $line.Substring($idx + 1)
        Set-Item -Path "Env:$name" -Value $value
    }
}

$vsDevCmd = Resolve-VsDevCmd
if (-not $vsDevCmd) {
    throw "run_julia_with_vsdevcmd: VsDevCmd.bat not found. Install Visual Studio Build Tools or set VSDEVCMD_BAT."
}

if (-not (Get-Command julia -ErrorAction SilentlyContinue)) {
    throw "run_julia_with_vsdevcmd: julia not found in PATH."
}

Import-VsDevEnvironment -VsDevCmdPath $vsDevCmd

if ($PlcaOnly) {
    $JuliaEntry = "julia/test_plca.jl"
}

Write-Host "run_julia_with_vsdevcmd: using $vsDevCmd"
Write-Host "run_julia_with_vsdevcmd: repo=$repoRoot"
Write-Host "run_julia_with_vsdevcmd: julia --project=$JuliaProject $JuliaEntry"
Write-Host "run_julia_with_vsdevcmd: VCINSTALLDIR=$($env:VCINSTALLDIR)"
Write-Host "run_julia_with_vsdevcmd: WindowsSdkDir=$($env:WindowsSdkDir)"

Push-Location $repoRoot
try {
    & julia --project=$JuliaProject $JuliaEntry
    if ($LASTEXITCODE -ne 0) {
        throw "Julia command failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

Write-Host "run_julia_with_vsdevcmd: ok"
