<#
.SYNOPSIS
  Installs and enrolls a pinned Wazuh agent on Windows. Run in an elevated PowerShell.
.DESCRIPTION
  Verifies the MSI's Authenticode signature (issued to Wazuh), installs it, writes the enrollment
  password to authd.pass (admin-only ACL) instead of passing it on a command line, then starts the agent.
  Re-running skips installation if the agent is already present.
#>
[CmdletBinding()]
param(
    [string]$Manager = '127.0.0.1',
    [string]$AgentName = "$($env:COMPUTERNAME)-win".ToLower(),
    [string]$Group = 'windows',
    [string]$Version = '4.14.8-1'
)
$ErrorActionPreference = 'Stop'
$logDir = Join-Path $env:ProgramData 'AegisSOC\logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Start-Transcript -Path (Join-Path $logDir "install-wazuh-agent-$(Get-Date -Format yyyyMMdd-HHmmss).log") | Out-Null

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}
if ($AgentName -notmatch '^[A-Za-z0-9._-]{1,128}$') { throw "Invalid agent name: $AgentName" }
if ($Group -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw "Invalid group: $Group" }

foreach ($port in 1514, 1515) {
    if (-not (Test-NetConnection -ComputerName $Manager -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue)) {
        throw "Cannot reach ${Manager}:$port"
    }
}

$agentDir = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$keys = Join-Path $agentDir 'client.keys'
function Test-Enrolled { (Test-Path $keys) -and (Get-Item $keys).Length -gt 0 }

if (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue) {
    Write-Output '[skip] Wazuh agent already installed'
} else {
    $msi = Join-Path $env:TEMP "wazuh-agent-$Version.msi"
    Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version.msi" -OutFile $msi -UseBasicParsing
    $sig = Get-AuthenticodeSignature -FilePath $msi
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Wazuh') {
        Remove-Item $msi
        throw "MSI signature check failed ($($sig.Status); $($sig.SignerCertificate.Subject))"
    }
    $msiArgs = @('/i', "`"$msi`"", '/qn', "WAZUH_MANAGER=$Manager", "WAZUH_REGISTRATION_SERVER=$Manager",
              "WAZUH_AGENT_NAME=$AgentName", "WAZUH_AGENT_GROUP=$Group")
    $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    Remove-Item $msi
    if ($proc.ExitCode -ne 0) { throw "msiexec failed with exit code $($proc.ExitCode)" }
}

if (Test-Enrolled) {
    Write-Output '[skip] Agent already has a key'
} else {
    $secure = Read-Host 'Enrollment password (WAZUH_ENROLLMENT_PASSWORD from .env)' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $passFile = Join-Path $agentDir 'authd.pass'
    # Restrict the file before the password is written so it is never readable by other users, even briefly.
    New-Item -ItemType File -Force -Path $passFile | Out-Null
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($id in 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'Allow')))
    }
    Set-Acl -Path $passFile -AclObject $acl
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr).Trim()
        if (-not $plain) { throw 'Empty enrollment password' }
        [IO.File]::WriteAllText($passFile, $plain, [Text.UTF8Encoding]::new($false))
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        Remove-Variable plain -ErrorAction SilentlyContinue
    }

    # Restart so a running agent re-reads authd.pass and retries enrollment immediately.
    Restart-Service WazuhSvc
    foreach ($i in 1..30) {
        if (Test-Enrolled) { break }
        Start-Sleep -Seconds 2
    }
    if (-not (Test-Enrolled)) {
        Write-Output (Get-Content (Join-Path $agentDir 'ossec.log') -Tail 10)
        throw ("Agent did not obtain a key. 'Invalid password': rerun and re-enter it. 'Invalid group': run " +
               "'aegis agent-config apply' on the stack host first so the '$Group' group exists.")
    }
}
if ((Get-Service WazuhSvc).Status -ne 'Running') { throw 'WazuhSvc is not running (see ossec.log)' }
Write-Output "[ok] Agent '$AgentName' enrolled in group '$Group'; confirm with 'aegis health'"
Stop-Transcript | Out-Null
