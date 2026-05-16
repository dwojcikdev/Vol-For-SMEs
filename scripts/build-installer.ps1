[CmdletBinding()]
param(
    [string]$InnoCompilerPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pyprojectPath = Join-Path $repoRoot "pyproject.toml"
$bundleBuilderPath = Join-Path $repoRoot "scripts\build-windows-bundle.py"
$installerScriptPath = Join-Path $repoRoot "installer\VolForSMEs.iss"
$launcherScriptPath = Join-Path $repoRoot "installer\LaunchVolForSMEs.vbs"
$launcherPythonPath = Join-Path $repoRoot "installer\launch_gui.pyw"
$bundlePath = Join-Path $repoRoot "dist\Vol For SMEs"

if (-not (Test-Path -LiteralPath $installerScriptPath)) {
    throw "Inno Setup script was not found: $installerScriptPath"
}

if (-not (Test-Path -LiteralPath $bundleBuilderPath)) {
    throw "Windows bundle builder script was not found: $bundleBuilderPath"
}

if (-not (Test-Path -LiteralPath $launcherScriptPath)) {
    throw "Installer launcher script was not found: $launcherScriptPath"
}

if (-not (Test-Path -LiteralPath $launcherPythonPath)) {
    throw "Installer Python launcher was not found: $launcherPythonPath"
}

$pyprojectText = Get-Content -LiteralPath $pyprojectPath -Raw
$versionMatch = [regex]::Match($pyprojectText, '(?m)^\s*version\s*=\s*"([^"]+)"\s*$')
if (-not $versionMatch.Success) {
    throw "Could not read the project version from $pyprojectPath"
}

$appVersion = $versionMatch.Groups[1].Value

$candidateCompilerPaths = @()

if ($InnoCompilerPath) {
    $candidateCompilerPaths += $InnoCompilerPath
}
if (${env:ProgramFiles(x86)}) {
    $candidateCompilerPaths += Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
}
if ($env:ProgramFiles) {
    $candidateCompilerPaths += Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"
}

$resolvedCompilerPath = $candidateCompilerPaths |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1

if (-not $resolvedCompilerPath) {
    throw (
        "Inno Setup 6 compiler (ISCC.exe) was not found. " +
        "Install Inno Setup 6 or pass -InnoCompilerPath with the full ISCC.exe path."
    )
}

$outputDirectory = Join-Path $repoRoot "dist\installer"
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

Write-Host "Building self-contained Windows app bundle..."
& python $bundleBuilderPath
if ($LASTEXITCODE -ne 0) {
    throw "Windows app bundle build failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $bundlePath)) {
    throw "Windows app bundle was not created: $bundlePath"
}

Write-Host "Using Inno Setup compiler: $resolvedCompilerPath"
Write-Host "Packaging installer for version: $appVersion"
Write-Host "Installer input: self-contained bundle in $bundlePath"

$arguments = @(
    "/DAppVersion=$appVersion",
    $installerScriptPath
)

& $resolvedCompilerPath @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compilation failed with exit code $LASTEXITCODE"
}

$generatedInstaller = Get-ChildItem -LiteralPath $outputDirectory -Filter "*.exe" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($null -eq $generatedInstaller) {
    throw "Inno Setup did not produce an installer in $outputDirectory"
}

Write-Host "Installer created: $($generatedInstaller.FullName)"
