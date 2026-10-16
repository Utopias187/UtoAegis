#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string] $ServiceName = 'UtoAegis'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Host "Service '$ServiceName' is not installed."
    return
}

if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Stop and remove Windows service registration')) {
    return
}

if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
    Stop-Service -Name $ServiceName
    $service.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(30))
}

& "$env:SystemRoot\System32\sc.exe" delete $ServiceName
if ($LASTEXITCODE -ne 0) {
    throw "Failed to remove service '$ServiceName'."
}

Write-Host 'Service registration removed. Published files, data, quarantine entries, and ACLs were preserved.'
