<#
.SYNOPSIS
    Builds the gecit MSI.

.DESCRIPTION
    Needs the WiX .NET tool on PATH:

        dotnet tool install --global wix --version 6.0.1
        wix extension add -g WixToolset.UI.wixext/6.0.1

    Pin the extensions to the same version as the tool. An unpinned
    `wix extension add` resolves a newer extension than the pinned tool and
    the build fails to link.

.PARAMETER Version
    Numeric MSI version, x.y.z for a release or x.y.z.N for a release
    candidate. Release tags carry a leading v, which is not valid here and has
    to be stripped by the caller.

    MSI compares only the first three fields, so 0.2.0.1 and 0.2.0 are the same
    version to the installer. That is what lets a release install over its own
    candidate, and it needs AllowSameVersionUpgrades, which gecit.wxs sets.

.PARAMETER BinaryPath
    Path to the gecit.exe to package.

.PARAMETER Label
    Name to put in the output filename, defaulting to Version. The tag is more
    recognisable than the numeric version for a candidate: 0.2.0-rc1 rather
    than 0.2.0.1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$BinaryPath,
    [string]$Label
)

$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') {
    throw "Version must be x.y.z or x.y.z.N, got '$Version'. MSI rejects anything else."
}

if (-not $Label) { $Label = $Version }

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw "wix is not on PATH. Install it with: dotnet tool install --global wix --version 6.0.1"
}

# Resolved before the Push-Location below, so a relative path means what the
# caller meant by it rather than something under packaging/windows.
$resolvedBinary = (Resolve-Path $BinaryPath).Path

Push-Location $PSScriptRoot
try {
    $output = Join-Path $PSScriptRoot "gecit-$Label-amd64.msi"

    Write-Host "building $output from $resolvedBinary"

    & wix build gecit.wxs `
        -arch x64 `
        -ext WixToolset.UI.wixext `
        -d Version="$Version" `
        -d BinaryPath="$resolvedBinary" `
        -out $output

    if ($LASTEXITCODE -ne 0) {
        throw "wix build failed with exit code $LASTEXITCODE"
    }

    Write-Host "built $output"
}
finally {
    Pop-Location
}
