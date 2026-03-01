#Requires -Version 5.1
<#
.SYNOPSIS
    Build script for the pwssh module.
.DESCRIPTION
    Downloads dependencies, runs tests, and prepares the module for distribution.
.PARAMETER Task
    The build task to run: Build, Test, Analyze, Clean, or Publish.
#>
[CmdletBinding()]
param(
    [ValidateSet('Build', 'Test', 'Analyze', 'Clean', 'Publish')]
    [string]$Task = 'Build'
)

$ErrorActionPreference = 'Stop'

$ModuleName   = 'pwssh'
$SrcPath      = Join-Path $PSScriptRoot 'src' $ModuleName
$OutputPath   = Join-Path $PSScriptRoot 'output' $ModuleName
$TestPath     = Join-Path $PSScriptRoot 'Tests'
$LibPath      = Join-Path $SrcPath 'lib'
$CSharpPath   = Join-Path $SrcPath 'Private' 'CSharp'
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

    # Compile PwSSH.Crypto.dll from C# source
    Build-CryptoAssembly

    # Copy module files
    Copy-Item -Path (Join-Path $SrcPath '*') -Destination $OutputPath -Recurse -Force

    # Remove raw C# source from output — only the compiled DLL ships
    $outputCSharpDir = Join-Path $OutputPath 'Private' 'CSharp'
    if (Test-Path $outputCSharpDir) {
        Remove-Item $outputCSharpDir -Recurse -Force
    }

    Write-Host "Build complete: $OutputPath" -ForegroundColor Green
}

function Build-CryptoAssembly {
    Write-Host "  Compiling PwSSH.Crypto..." -ForegroundColor Yellow

    $csprojPath = Join-Path $CSharpPath 'PwSSH.Crypto.csproj'
    if (-not (Test-Path $csprojPath)) {
        throw "Cannot find PwSSH.Crypto.csproj at $csprojPath"
    }

    # Verify dotnet SDK is available
    try {
        $null = & dotnet --version 2>&1
    }
    catch {
        throw "dotnet SDK not found. Install .NET SDK 6.0+ from https://dot.net/download"
    }

    # Build the DLL
    & dotnet build $csprojPath -c Release -o (Join-Path $CSharpPath 'bin' 'publish') --nologo -v quiet
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet build failed for PwSSH.Crypto (exit code $LASTEXITCODE)"
    }

    # Copy DLL to lib/ alongside Renci.SshNet.dll
    New-Item -Path $LibPath -ItemType Directory -Force | Out-Null
    $builtDll = Join-Path $CSharpPath 'bin' 'publish' 'PwSSH.Crypto.dll'
    if (-not (Test-Path $builtDll)) {
        throw "Build produced no output: $builtDll not found"
    }
    Copy-Item $builtDll -Destination $LibPath -Force

    # Generate integrity hash
    $installedDll = Join-Path $LibPath 'PwSSH.Crypto.dll'
    $hash = (Get-FileHash -Path $installedDll -Algorithm SHA256).Hash.ToUpperInvariant()
    [System.IO.File]::WriteAllText((Join-Path $LibPath 'PwSSH.Crypto.dll.sha256'), $hash)
    Write-Host "  Compiled PwSSH.Crypto.dll - SHA256: $hash" -ForegroundColor Green
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
                # Generate integrity hash file for runtime verification
                $installedDll = Join-Path $LibPath 'Renci.SshNet.dll'
                $hash = (Get-FileHash -Path $installedDll -Algorithm SHA256).Hash.ToUpperInvariant()
                [System.IO.File]::WriteAllText((Join-Path $LibPath 'Renci.SshNet.dll.sha256'), $hash)
                Write-Host "  Installed Renci.SshNet.dll ($tfm) - SHA256: $hash" -ForegroundColor Green
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

function Invoke-Analyze {
    Write-Host "=== Running PSScriptAnalyzer ===" -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Write-Host "Installing PSScriptAnalyzer..." -ForegroundColor Yellow
        Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
    }

    $settingsPath = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
    $analyzerParams = @{
        Path     = $OutputPath
        Recurse  = $true
        Severity = @('Error', 'Warning')
    }
    if (Test-Path $settingsPath) {
        $analyzerParams['Settings'] = $settingsPath
    }

    $findings = Invoke-ScriptAnalyzer @analyzerParams
    if ($findings) {
        $findings | Format-Table -AutoSize
        throw "$($findings.Count) PSScriptAnalyzer finding(s) with severity Error or Warning."
    }
    Write-Host "PSScriptAnalyzer passed — no errors or warnings." -ForegroundColor Green
}

function Invoke-Clean {
    Write-Host "=== Cleaning ===" -ForegroundColor Cyan
    @(
        $OutputPath,
        (Join-Path $PSScriptRoot 'TestResults'),
        (Join-Path $CSharpPath 'bin'),
        (Join-Path $CSharpPath 'obj')
    ) | ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Recurse -Force }
    }
    Write-Host "Clean complete." -ForegroundColor Green
}

function Invoke-Publish {
    Write-Host "=== Publishing $ModuleName to PSGallery ===" -ForegroundColor Cyan

    if (-not $env:NUGET_API_KEY) {
        throw "Cannot publish: `$env:NUGET_API_KEY is not set. Get your API key from https://www.powershellgallery.com/account/apikeys"
    }

    # Validate the module manifest before publishing
    $manifestPath = Join-Path $OutputPath "$ModuleName.psd1"
    Test-ModuleManifest -Path $manifestPath -ErrorAction Stop | Out-Null
    Write-Host "  Manifest validation passed." -ForegroundColor Green

    Publish-Module -Path $OutputPath -NuGetApiKey $env:NUGET_API_KEY -Repository PSGallery
    Write-Host "Published $ModuleName to PSGallery." -ForegroundColor Green
}

switch ($Task) {
    'Build'   { Invoke-Build }
    'Test'    { Invoke-Build; Invoke-Tests }
    'Analyze' { Invoke-Build; Invoke-Analyze }
    'Clean'   { Invoke-Clean }
    'Publish' { Invoke-Build; Invoke-Tests; Invoke-Analyze; Invoke-Publish }
}
