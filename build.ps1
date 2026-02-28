#Requires -Version 5.1
<#
.SYNOPSIS
    Build script for the pwssh module.
.DESCRIPTION
    Downloads dependencies, runs tests, and prepares the module for distribution.
.PARAMETER Task
    The build task to run: Build, Test, Clean, or Publish.
#>
[CmdletBinding()]
param(
    [ValidateSet('Build', 'Test', 'Clean', 'Publish')]
    [string]$Task = 'Build'
)

$ErrorActionPreference = 'Stop'

$ModuleName   = 'pwssh'
$SrcPath      = Join-Path $PSScriptRoot 'src' $ModuleName
$OutputPath   = Join-Path $PSScriptRoot 'output' $ModuleName
$TestPath     = Join-Path $PSScriptRoot 'Tests'
$LibPath      = Join-Path $SrcPath 'lib'
$NuGetPkgName = 'SSH.NET'
$NuGetPkgVer  = '2024.2.0'

function Invoke-Build {
    Write-Host "=== Building $ModuleName ===" -ForegroundColor Cyan

    # Clean output
    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Recurse -Force }
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

    # Download SSH.NET if not present
    if (-not (Test-Path (Join-Path $LibPath 'Renci.SshNet.dll'))) {
        Write-Host "Downloading $NuGetPkgName $NuGetPkgVer..." -ForegroundColor Yellow
        Install-SshNetPackage
    }

    # Copy module files
    Copy-Item -Path (Join-Path $SrcPath '*') -Destination $OutputPath -Recurse -Force

    Write-Host "Build complete: $OutputPath" -ForegroundColor Green
}

function Install-SshNetPackage {
    New-Item -Path $LibPath -ItemType Directory -Force | Out-Null
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_nuget_$([guid]::NewGuid().ToString('N'))"
    New-Item -Path $tmpDir -ItemType Directory -Force | Out-Null

    try {
        $nugetUrl = "https://api.nuget.org/v3-flatcontainer/$($NuGetPkgName.ToLower())/$NuGetPkgVer/$($NuGetPkgName.ToLower()).$NuGetPkgVer.nupkg"
        $nupkgPath = Join-Path $tmpDir "$NuGetPkgName.nupkg"
        Invoke-WebRequest -Uri $nugetUrl -OutFile $nupkgPath

        $extractPath = Join-Path $tmpDir 'extracted'
        Expand-Archive -Path $nupkgPath -DestinationPath $extractPath

        # Prefer net8.0 > net6.0 > netstandard2.0
        $tfms = @('net8.0', 'net6.0', 'netstandard2.0')
        foreach ($tfm in $tfms) {
            $dllPath = Join-Path $extractPath 'lib' $tfm 'Renci.SshNet.dll'
            if (Test-Path $dllPath) {
                Copy-Item $dllPath -Destination $LibPath -Force
                Write-Host "  Installed Renci.SshNet.dll ($tfm)" -ForegroundColor Green
                return
            }
        }
        throw "Could not find Renci.SshNet.dll in any supported TFM"
    }
    finally {
        Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Tests {
    Write-Host "=== Running Tests ===" -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name Pester | Where-Object Version -ge '5.0.0')) {
        Write-Host "Installing Pester 5..." -ForegroundColor Yellow
        Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -Scope CurrentUser
    }

    $config = New-PesterConfiguration
    $config.Run.Path = $TestPath
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Detailed'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $PSScriptRoot 'TestResults' 'testResults.xml'

    $results = Invoke-Pester -Configuration $config

    if ($results.FailedCount -gt 0) {
        throw "$($results.FailedCount) test(s) failed."
    }
    Write-Host "All $($results.PassedCount) tests passed." -ForegroundColor Green
}

function Invoke-Clean {
    Write-Host "=== Cleaning ===" -ForegroundColor Cyan
    @($OutputPath, (Join-Path $PSScriptRoot 'TestResults')) | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Recurse -Force }
    }
    Write-Host "Clean complete." -ForegroundColor Green
}

switch ($Task) {
    'Build'   { Invoke-Build }
    'Test'    { Invoke-Build; Invoke-Tests }
    'Clean'   { Invoke-Clean }
    'Publish' { Invoke-Build; Write-Host 'Publish not yet implemented' -ForegroundColor Yellow }
}
