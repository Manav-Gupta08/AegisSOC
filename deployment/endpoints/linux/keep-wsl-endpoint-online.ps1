<#
.SYNOPSIS
  Keeps a WSL distro running so its Wazuh agent is not stopped by WSL idle shutdown.
.DESCRIPTION
  Without a long-lived process, WSL terminates the distro shortly after the last command exits,
  stopping the agent and losing events written during shutdown (see reports/examples/M1-E2E-001).
  -Register creates a per-user logon Scheduled Task; -Unregister removes it. No admin rights needed.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [string]$Distro = 'Ubuntu',
    [Parameter(ParameterSetName = 'Register')][switch]$Register,
    [Parameter(ParameterSetName = 'Unregister')][switch]$Unregister
)
$ErrorActionPreference = 'Stop'
$taskName = "AegisSOC-WSL-Endpoint-$Distro"

if ($Distro -notmatch '^[A-Za-z0-9._-]+$') { throw "Invalid distro name: $Distro" }

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Output "Removed scheduled task $taskName"
    return
}

if ($Register) {
    $action = New-ScheduledTaskAction -Execute 'wsl.exe' -Argument "-d $Distro -- sleep infinity"
    $logon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    # Re-check every 5 minutes; IgnoreNew makes this a no-op while the keep-alive is still running.
    $repeat = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -Hidden -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $logon, $repeat -Settings $settings -Force `
        -Description 'AegisSOC: keep WSL endpoint online for continuous telemetry' | Out-Null
    Start-ScheduledTask -TaskName $taskName
    Write-Output "Registered and started scheduled task $taskName"
    return
}

& wsl.exe -d $Distro -- sleep infinity
