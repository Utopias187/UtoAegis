#Requires -Version 7.0
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $PublishDirectory,

    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string] $ServiceName = 'UtoAegis',

    [switch] $AllowQuarantineResponse,

    [switch] $Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ConfiguredPath {
    param(
        [AllowNull()]
        [string] $Value,
        [string] $BaseDirectory
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($Value.Trim())
    if ([IO.Path]::IsPathRooted($expanded)) {
        return [IO.Path]::GetFullPath($expanded)
    }

    return [IO.Path]::GetFullPath($expanded, $BaseDirectory)
}

function Invoke-Sc {
    param([Parameter(ValueFromRemainingArguments)][string[]] $Arguments)

    & "$env:SystemRoot\System32\sc.exe" @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed with exit code $LASTEXITCODE."
    }
}

function Set-DirectoryGrant {
    param(
        [string] $Path,
        [string] $Identity,
        [ValidateSet('RX', 'M')]
        [string] $Rights,
        [switch] $Create
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -eq [IO.Path]::GetPathRoot($fullPath)) {
        throw "Refusing to grant service access to filesystem root $fullPath"
    }

    if ($Create -and -not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $fullPath -PathType Container)) {
        throw "Required directory does not exist: $fullPath"
    }

    & "$env:SystemRoot\System32\icacls.exe" $fullPath /grant "${Identity}:(OI)(CI)$Rights"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to grant $Rights access to $fullPath"
    }
}

$publish = (Resolve-Path -LiteralPath $PublishDirectory).Path
$executable = Join-Path $publish 'utoaegis-service.exe'
$settingsPath = Join-Path $publish 'appsettings.json'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Service executable not found: $executable"
}

if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw "Service configuration not found: $settingsPath"
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service '$ServiceName' already exists. Remove it before reinstalling."
}

$document = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
$settings = $document.UtoAegis
$responseMode = if ([string]::IsNullOrWhiteSpace([string]$settings.Response.Mode)) {
    'ObserveOnly'
} else {
    [string]$settings.Response.Mode
}
if ($responseMode -eq 'Quarantine' -and -not $AllowQuarantineResponse) {
    throw 'Quarantine mode requires the explicit -AllowQuarantineResponse installer switch.'
}

& $executable --validate-config
if ($LASTEXITCODE -ne 0) {
    throw 'Service configuration validation failed.'
}

$monitorRoot = Resolve-ConfiguredPath ([string]$settings.MonitorRoot) $publish
$databasePath = Resolve-ConfiguredPath ([string]$settings.DatabasePath) $publish
$historyPath = Resolve-ConfiguredPath ([string]$settings.HistoryPath) $publish
$vaultPath = Resolve-ConfiguredPath ([string]$settings.VaultPath) $publish
$signaturePath = Resolve-ConfiguredPath ([string]$settings.SignaturePath) $publish
$serviceIdentity = "NT SERVICE\$ServiceName"
$binaryPath = '"' + $executable + '"'

if (-not $PSCmdlet.ShouldProcess($ServiceName, 'Install and configure Windows service')) {
    return
}

$created = $false
try {
    Invoke-Sc create $ServiceName 'binPath=' $binaryPath 'start=' 'delayed-auto' `
        'error=' 'normal' 'obj=' $serviceIdentity 'DisplayName=' 'UtoAegis Endpoint Monitor'
    $created = $true
    Invoke-Sc description $ServiceName 'Supervised UtoAegis file monitoring and detection response.'
    Invoke-Sc failure $ServiceName 'reset=' '86400' 'actions=' 'restart/60000/restart/60000/""/0'
    Invoke-Sc failureflag $ServiceName '1'

    Set-DirectoryGrant $publish $serviceIdentity 'RX'
    Set-DirectoryGrant $monitorRoot $serviceIdentity 'RX'

    $writeDirectories = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($filePath in @($databasePath, $historyPath)) {
        if ($null -ne $filePath) {
            [void]$writeDirectories.Add([IO.Path]::GetDirectoryName($filePath))
        }
    }

    if ($null -ne $vaultPath) {
        [void]$writeDirectories.Add($vaultPath)
    }

    foreach ($directory in $writeDirectories) {
        Set-DirectoryGrant $directory $serviceIdentity 'M' -Create
    }

    if ($null -ne $signaturePath) {
        & "$env:SystemRoot\System32\icacls.exe" $signaturePath /grant "${serviceIdentity}:R"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to grant read access to $signaturePath"
        }
    }

    if (-not [Diagnostics.EventLog]::SourceExists('UtoAegis')) {
        New-EventLog -LogName Application -Source UtoAegis
    }

    if ($Start) {
        Start-Service -Name $ServiceName
    }
} catch {
    if ($created) {
        & "$env:SystemRoot\System32\sc.exe" delete $ServiceName | Out-Null
    }

    throw
}

Write-Host "Installed $ServiceName as $serviceIdentity in $responseMode mode."
if (-not $Start) {
    Write-Host "Start it with: Start-Service -Name '$ServiceName'"
}
