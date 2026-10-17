#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $IndicatorsPath,

    [Parameter(Mandatory)]
    [string] $SignaturesPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$')]
    [string] $Version,

    [Parameter(Mandatory)]
    [ValidateRange(1, [long]::MaxValue)]
    [long] $Sequence,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$')]
    [string] $KeyId,

    [Parameter(Mandatory)]
    [string] $PrivateKeyPath,

    [Parameter(Mandatory)]
    [string] $OutputDirectory,

    [ValidateRange(1, 14)]
    [int] $ValidityDays = 7
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RegularFile {
    param([string] $Path, [string] $Label)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Label must be a regular file and cannot be a reparse point."
    }

    return $item.FullName
}

function Get-ContentDescriptor {
    param([string] $Kind, [string] $Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.LongLength -le 0 -or $bytes.LongLength -gt 536870912) {
        throw "$Kind content must contain 1 to 536870912 bytes."
    }

    return [ordered]@{
        kind = $Kind
        sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        length = $bytes.LongLength
    }
}

$indicators = Resolve-RegularFile $IndicatorsPath 'IndicatorsPath'
$signatures = Resolve-RegularFile $SignaturesPath 'SignaturesPath'
$privateKey = Resolve-RegularFile $PrivateKeyPath 'PrivateKeyPath'
if ((Get-Item -LiteralPath $privateKey).Length -gt 16384) {
    throw 'PrivateKeyPath exceeds the 16384-byte limit.'
}

$output = [IO.Path]::GetFullPath($OutputDirectory, (Get-Location).Path)
if ([IO.Path]::TrimEndingDirectorySeparator($output) -eq
    [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetPathRoot($output))) {
    throw 'OutputDirectory cannot be a filesystem root.'
}

if (Test-Path -LiteralPath $output) {
    throw "OutputDirectory already exists: $output"
}

$parent = [IO.Path]::GetDirectoryName($output)
if ([string]::IsNullOrWhiteSpace($parent)) {
    throw 'OutputDirectory must have a parent directory.'
}

[IO.Directory]::CreateDirectory($parent) | Out-Null
$staging = Join-Path $parent ('.utoaegis-bundle-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($staging) | Out-Null

try {
    Copy-Item -LiteralPath $indicators -Destination (Join-Path $staging 'indicators.jsonl')
    Copy-Item -LiteralPath $signatures -Destination (Join-Path $staging 'signatures.jsonl')
    $stagedIndicators = Join-Path $staging 'indicators.jsonl'
    $stagedSignatures = Join-Path $staging 'signatures.jsonl'

    $publishedUtc = [DateTimeOffset]::UtcNow
    $manifest = [ordered]@{
        schemaVersion = 1
        algorithm = 'ecdsa-p256-sha256'
        sequence = $Sequence
        version = $Version
        keyId = $KeyId
        publishedUtc = $publishedUtc.ToString('O', [Globalization.CultureInfo]::InvariantCulture)
        expiresUtc = $publishedUtc.AddDays($ValidityDays).ToString(
            'O',
            [Globalization.CultureInfo]::InvariantCulture)
        contents = @(
            Get-ContentDescriptor 'hash-indicators' $stagedIndicators
            Get-ContentDescriptor 'byte-signatures' $stagedSignatures
        )
    }

    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $manifestBytes = $utf8.GetBytes(($manifest | ConvertTo-Json -Depth 4 -Compress))
    $manifestPath = Join-Path $staging 'manifest.json'
    [IO.File]::WriteAllBytes($manifestPath, $manifestBytes)

    $pem = [IO.File]::ReadAllText($privateKey, $utf8)
    $key = [Security.Cryptography.ECDsa]::Create()
    try {
        $key.ImportFromPem($pem)
        $parameters = $key.ExportParameters($true)
        if ($parameters.Curve.Oid.Value -ne '1.2.840.10045.3.1.7' -or $null -eq $parameters.D) {
            throw 'PrivateKeyPath must contain an ECDSA NIST P-256 private key.'
        }

        $signature = $key.SignData(
            $manifestBytes,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        [IO.File]::WriteAllText(
            (Join-Path $staging 'manifest.sig'),
            [Convert]::ToBase64String($signature),
            $utf8)
    } finally {
        $key.Dispose()
    }

    [IO.Directory]::Move($staging, $output)
} catch {
    if (Test-Path -LiteralPath $staging -PathType Container) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }

    throw
}

Write-Host "Created signed threat bundle $output"
Write-Host "Version $Version; sequence $Sequence; signing key $KeyId."
