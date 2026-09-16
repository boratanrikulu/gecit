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
    Numeric MSI version, x.y.z. Release tags carry a leading v, which is not
    valid here and has to be stripped by the caller.

.PARAMETER BinaryPath
    Path to the gecit.exe to package.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$BinaryPath
)

$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must be numeric x.y.z, got '$Version'. MSI rejects anything else, and only the first three fields are compared for upgrades."
}

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw "wix is not on PATH. Install it with: dotnet tool install --global wix --version 6.0.1"
}

Push-Location $PSScriptRoot
try {
    $resolvedBinary = (Resolve-Path $BinaryPath).Path
    $output = Join-Path $PSScriptRoot "gecit-$Version-amd64.msi"

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
