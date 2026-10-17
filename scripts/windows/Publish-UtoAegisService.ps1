#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$project = Join-Path $repositoryRoot 'src/UtoAegis.Service/UtoAegis.Service.csproj'
$cliProject = Join-Path $repositoryRoot 'src/UtoAegis.Cli/UtoAegis.Cli.csproj'
$output = [IO.Path]::GetFullPath($OutputDirectory, (Get-Location).Path)
$toolsOutput = Join-Path $output 'tools'

dotnet restore (Join-Path $repositoryRoot 'UtoAegis.slnx') --locked-mode
if ($LASTEXITCODE -ne 0) {
    throw 'Locked dependency restore failed.'
}

dotnet test (Join-Path $repositoryRoot 'UtoAegis.slnx') --configuration Release --no-restore
if ($LASTEXITCODE -ne 0) {
    throw 'Release tests failed.'
}

dotnet publish $project --configuration Release --no-restore --output $output
if ($LASTEXITCODE -ne 0) {
    throw 'Service publication failed.'
}

dotnet publish $cliProject --configuration Release --no-restore --output $toolsOutput
if ($LASTEXITCODE -ne 0) {
    throw 'Operator CLI publication failed.'
}

Write-Host "Published the framework-dependent Windows service to $output"
Write-Host "Published the operator CLI to $toolsOutput"
Write-Host 'Edit appsettings.json and run the installer from an elevated PowerShell session.'
