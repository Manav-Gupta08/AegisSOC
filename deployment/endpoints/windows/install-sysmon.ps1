<#
.SYNOPSIS
  Installs or updates Sysmon with the AegisSOC configuration. Run in an elevated PowerShell.
.DESCRIPTION
  Downloads Sysmon from Sysinternals, verifies the Authenticode signature is valid and issued to
  Microsoft, then installs (or reconfigures) it. Re-running only updates the configuration.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'sysmon-aegis.xml'),
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AegisSOC\Sysmon')
)
$ErrorActionPreference = 'Stop'
$logDir = Join-Path $env:ProgramData 'AegisSOC\logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Start-Transcript -Path (Join-Path $logDir "install-sysmon-$(Get-Date -Format yyyyMMdd-HHmmss).log") | Out-Null

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}
[xml](Get-Content -Raw $ConfigPath) | Out-Null

function Assert-MicrosoftSigned([string]$Path) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Signature check failed for $Path ($($sig.Status); $($sig.SignerCertificate.Subject))"
    }
}

$service = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
$exe = Join-Path $InstallDir 'Sysmon64.exe'

if (-not $service) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $zip = Join-Path $env:TEMP 'Sysmon.zip'
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
    Remove-Item $zip
    Assert-MicrosoftSigned $exe
    & $exe -accepteula -i $ConfigPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed with exit code $LASTEXITCODE" }
    Write-Output '[ok] Sysmon installed'
} else {
    if (-not (Test-Path $exe)) { $exe = (Get-CimInstance Win32_Service -Filter "Name='Sysmon64'").PathName.Trim('"') }
    Assert-MicrosoftSigned $exe
    & $exe -c $ConfigPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Sysmon config update failed with exit code $LASTEXITCODE" }
    Write-Output '[ok] Sysmon configuration updated'
}

if ((Get-Service Sysmon64).Status -ne 'Running') { throw 'Sysmon64 service is not running' }
$recent = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue
Write-Output "[ok] Sysmon64 running; latest event: $($recent.TimeCreated)"
Stop-Transcript | Out-Null
