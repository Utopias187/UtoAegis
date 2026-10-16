#Requires -Version 7.0
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string] $ServiceName = 'UtoAegis',
    [ValidateRange(1, 100)]
    [int] $EventCount = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($null -eq $service) {
    throw "Service '$ServiceName' is not installed."
}

[pscustomobject]@{
    Name = $service.Name
    State = $service.State
    StartMode = $service.StartMode
    StartName = $service.StartName
    ProcessId = $service.ProcessId
    PathName = $service.PathName
}

Write-Host "`nRecent UtoAegis Application log events:"
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'UtoAegis' } `
    -MaxEvents $EventCount -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message
