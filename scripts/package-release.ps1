param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$DistDir = 'dist',
    [string]$ReleaseDir = 'release',
    [string]$ExeName = 'ProtocolHarbor.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ProjectVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VersionFile
    )

    $content = Get-Content -Path $VersionFile -Raw -Encoding UTF8
    $match = [regex]::Match($content, '__version__\s*=\s*["''](?<version>[^"'']+)["'']')
    if (-not $match.Success) {
        throw "Could not read __version__ from $VersionFile"
    }

    return $match.Groups['version'].Value
}

$projectRootPath = (Resolve-Path $ProjectRoot).Path
$distPath = Join-Path $projectRootPath $DistDir
$releasePath = Join-Path $projectRootPath $ReleaseDir
$version = Get-ProjectVersion -VersionFile (Join-Path $projectRootPath 'version.py')
$releaseBaseName = "ProtocolHarbor-$version-win64"
$stagingPath = Join-Path $releasePath $releaseBaseName
$exePath = Join-Path $distPath $ExeName
$zipPath = Join-Path $releasePath ($releaseBaseName + '.zip')
$checksumPath = Join-Path $releasePath ($releaseBaseName + '.sha256.txt')
$includedFiles = @(
    'README.md',
    'LICENSE',
    'CHANGELOG.md'
)

if (-not (Test-Path -Path $exePath -PathType Leaf)) {
    throw "Expected built executable at $exePath. Run PyInstaller first."
}

New-Item -ItemType Directory -Path $releasePath -Force | Out-Null

if (Test-Path -Path $stagingPath) {
    Remove-Item -Path $stagingPath -Recurse -Force
}

if (Test-Path -Path $zipPath) {
    Remove-Item -Path $zipPath -Force
}

New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
Copy-Item -Path $exePath -Destination (Join-Path $stagingPath $ExeName)

foreach ($relativePath in $includedFiles) {
    $sourcePath = Join-Path $projectRootPath $relativePath
    if (Test-Path -Path $sourcePath -PathType Leaf) {
        Copy-Item -Path $sourcePath -Destination (Join-Path $stagingPath $relativePath)
    }
}

Compress-Archive -Path $stagingPath -DestinationPath $zipPath -CompressionLevel Optimal -Force

$exeHash = Get-FileHash -Path $exePath -Algorithm SHA256
$zipHash = Get-FileHash -Path $zipPath -Algorithm SHA256
$hashTargets = @($exeHash, $zipHash)

$checksumLines = foreach ($hashTarget in $hashTargets) {
    '{0} *{1}' -f $hashTarget.Hash.ToLowerInvariant(), (Split-Path -Path $hashTarget.Path -Leaf)
}
$checksumLines | Set-Content -Path $checksumPath -Encoding ASCII

Write-Host "Release package created: $zipPath"
Write-Host "Checksums written: $checksumPath"
