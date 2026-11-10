#Requires -Version 5.1
<#
.SYNOPSIS
    Build script for the pwssh module.
.DESCRIPTION
    Downloads the pinned dependencies, runs tests, and stages the module in ./output.
.PARAMETER Task
    Build       - download dependencies (if missing) and stage the module in ./output/pwssh
    Test        - Build, then run the unit tests
    Integration - Build, then run the integration tests (see Tests/Integration)
    Clean       - remove ./output, ./TestResults and the downloaded dependencies
.EXAMPLE
    ./build.ps1 -Task Test
#>
[CmdletBinding()]
param(
    [ValidateSet('Build', 'Test', 'Integration', 'Clean')]
    [string]$Task = 'Build'
)

$ErrorActionPreference = 'Stop'

$ModuleName = 'pwssh'
$SrcPath    = Join-Path (Join-Path $PSScriptRoot 'src') $ModuleName
$OutputPath = Join-Path (Join-Path $PSScriptRoot 'output') $ModuleName
$TestPath   = Join-Path $PSScriptRoot 'Tests'
$LibPath    = Join-Path $SrcPath 'lib'

# Every dependency is pinned to an exact version and to the SHA-256 of its .nupkg.
# A download whose hash differs is rejected. To update a package, change the version,
# verify the new package, and replace the hash.
#   Core    = folder under lib/ in the package for PowerShell 7.2+ (.NET 6+)
#   Desktop = folder under lib/ in the package for Windows PowerShell 5.1 (.NET Framework 4.7.2+)
$Dependencies = @(
    @{ Id = 'SSH.NET';                                 Version = '2024.2.0'; Sha256 = '0873CF5E9D72BD25C509CA86CB57E8301923E2DC2162E93207968B16C153894E'; Core = 'net6.0'; Desktop = 'net462' }
    @{ Id = 'BouncyCastle.Cryptography';               Version = '2.4.0';    Sha256 = '0E80D9356B5833ED0E2C872538467EB637065F2986957BDDBEAD9930F9A20090'; Core = 'net6.0'; Desktop = 'net461' }
    @{ Id = 'Microsoft.Bcl.AsyncInterfaces';           Version = '1.0.0';    Sha256 = '702DBDB25F38878B95C89AB620F891364D46DBB671FC46E7EE12CF5DB32ABD01'; Desktop = 'net461' }
    @{ Id = 'System.Formats.Asn1';                     Version = '8.0.1';    Sha256 = '99ACBF5A0F9EB269B5375E244131B81123018BE19028FA7466BAC1A3FA3A3973'; Desktop = 'net462' }
    @{ Id = 'System.Threading.Tasks.Extensions';       Version = '4.5.2';    Sha256 = '12A245F53A693074CABE947A7A6ADD03AD736A5316DC7C2B67B8FA067E1B06EA'; Desktop = 'netstandard2.0' }
    @{ Id = 'System.Runtime.CompilerServices.Unsafe';  Version = '4.5.3';    Sha256 = '96764C52A44EE1161151E48EF07489F72047A851CB55B99E9F01D6908536D1A9'; Desktop = 'net461' }
    @{ Id = 'System.Buffers';                          Version = '4.5.1';    Sha256 = 'C30B3DD2C7E2F4CEE4B823D692FD42118309B42AB1F5007F923D329A5B0D6B12'; Desktop = 'net461' }
    @{ Id = 'System.Memory';                           Version = '4.5.5';    Sha256 = '10F43DA352A29FB2B3188E4EDD4DCF5100194C8B526E4F61FE2E2B5623775A22'; Desktop = 'net461' }
    @{ Id = 'System.Numerics.Vectors';                 Version = '4.5.0';    Sha256 = 'A9D49320581FDA1B4F4BE6212C68C01A22CDF228026099C20A8EABEFCF90F9CF'; Desktop = 'net46' }
    @{ Id = 'System.ValueTuple';                       Version = '4.5.0';    Sha256 = '9E21FA9767D4E76BC0CEE065C1D40CC34384A114BFEC4D70E6C981168A926802'; Desktop = 'net47' }
)

function Test-DependenciesPresent {
    foreach ($dep in $Dependencies) {
        foreach ($edition in 'Core', 'Desktop') {
            if (-not $dep[$edition]) { continue }
            $marker = Join-Path (Join-Path $LibPath $edition.ToLower()) "$($dep.Id).$($dep.Version).ok"
            if (-not (Test-Path -LiteralPath $marker)) { return $false }
        }
    }
    return $true
}

function Install-Dependencies {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

    # Start from a clean lib/ so stale assemblies from an older pin cannot linger
    if (Test-Path -LiteralPath $LibPath) { Remove-Item -LiteralPath $LibPath -Recurse -Force }

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_nuget_$([guid]::NewGuid().ToString('N'))"
    New-Item -Path $tmpDir -ItemType Directory -Force | Out-Null

    try {
        foreach ($dep in $Dependencies) {
            $id = $dep.Id.ToLower()
            $url = "https://api.nuget.org/v3-flatcontainer/$id/$($dep.Version)/$id.$($dep.Version).nupkg"
            $nupkg = Join-Path $tmpDir "$id.$($dep.Version).nupkg"

            Write-Host "  $($dep.Id) $($dep.Version)" -ForegroundColor Yellow
            Invoke-WebRequest -Uri $url -OutFile $nupkg -UseBasicParsing

            $actual = (Get-FileHash -LiteralPath $nupkg -Algorithm SHA256).Hash
            if ($actual -ne $dep.Sha256) {
                throw "Hash mismatch for $($dep.Id) $($dep.Version): expected $($dep.Sha256), got $actual. Refusing to use the download."
            }

            $zip = [System.IO.Compression.ZipFile]::OpenRead($nupkg)
            try {
                foreach ($edition in 'Core', 'Desktop') {
                    $tfm = $dep[$edition]
                    if (-not $tfm) { continue }

                    $destDir = Join-Path $LibPath $edition.ToLower()
                    New-Item -Path $destDir -ItemType Directory -Force | Out-Null

                    $dlls = @($zip.Entries | Where-Object { $_.FullName -like "lib/$tfm/*.dll" })
                    if ($dlls.Count -eq 0) {
                        throw "$($dep.Id) $($dep.Version) has no assemblies under lib/$tfm"
                    }
                    foreach ($entry in $dlls) {
                        $dest = Join-Path $destDir $entry.Name
                        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
                    }
                    # Marker so an interrupted download is detected and redone
                    Set-Content -LiteralPath (Join-Path $destDir "$($dep.Id).$($dep.Version).ok") -Value $dep.Sha256
                }
            }
            finally {
                $zip.Dispose()
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Build {
    Write-Host "=== Building $ModuleName ===" -ForegroundColor Cyan

    if (-not (Test-DependenciesPresent)) {
        Write-Host 'Downloading dependencies...' -ForegroundColor Yellow
        Install-Dependencies
    }

    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    Copy-Item -Path (Join-Path $SrcPath '*') -Destination $OutputPath -Recurse -Force
    Get-ChildItem -LiteralPath $OutputPath -Recurse -Filter '*.ok' | Remove-Item -Force

    Write-Host "Build complete: $OutputPath" -ForegroundColor Green
}

function Invoke-Tests {
    param([string]$Suite)

    Write-Host "=== Running $Suite tests ===" -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name Pester | Where-Object Version -ge '5.0.0')) {
        Write-Host 'Installing Pester 5...' -ForegroundColor Yellow
        Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -Scope CurrentUser -SkipPublisherCheck
    }
    Import-Module Pester -MinimumVersion 5.0.0

    $resultDir = Join-Path $PSScriptRoot 'TestResults'
    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $TestPath $Suite
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Detailed'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $resultDir "$Suite.xml"

    $results = Invoke-Pester -Configuration $config

    if ($results.FailedCount -gt 0 -or $results.FailedContainersCount -gt 0 -or $results.FailedBlocksCount -gt 0) {
        throw "$Suite tests failed: $($results.FailedCount) test(s), $($results.FailedContainersCount) file(s), $($results.FailedBlocksCount) block(s)."
    }
    if ($results.PassedCount -eq 0) {
        throw "$Suite tests: nothing ran."
    }
    Write-Host "$Suite tests: $($results.PassedCount) passed, $($results.SkippedCount) skipped." -ForegroundColor Green
}

function Invoke-Clean {
    Write-Host '=== Cleaning ===' -ForegroundColor Cyan
    @((Join-Path $PSScriptRoot 'output'), (Join-Path $PSScriptRoot 'TestResults'), $LibPath) | ForEach-Object {
        if (Test-Path -LiteralPath $_) { Remove-Item -LiteralPath $_ -Recurse -Force }
    }
    Write-Host 'Clean complete.' -ForegroundColor Green
}

switch ($Task) {
    'Build'       { Invoke-Build }
    'Test'        { Invoke-Build; Invoke-Tests -Suite 'Unit' }
    'Integration' { Invoke-Build; Invoke-Tests -Suite 'Integration' }
    'Clean'       { Invoke-Clean }
}
