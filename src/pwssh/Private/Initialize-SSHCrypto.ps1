function Initialize-SSHCrypto {
    <#
    .SYNOPSIS
        Loads the pre-compiled PwSSH.Crypto assembly.
        Idempotent — skips if already loaded.
    .DESCRIPTION
        Loads PwSSH.Crypto.dll from the module's lib directory with SHA-256
        integrity verification. The DLL is compiled at build time from
        SSHCrypto.cs via 'dotnet build' (see build.ps1).
    #>
    [CmdletBinding()]
    param()

    if ([System.Management.Automation.PSTypeName]'PwSSH.Crypto.Ed25519' -as [type]) {
        Write-Verbose 'PwSSH.Crypto types already loaded.'
        return
    }

    # Resolve path: Private/Initialize-SSHCrypto.ps1 -> ../lib/PwSSH.Crypto.dll
    $moduleRoot = Split-Path $PSScriptRoot -Parent
    $dllPath = Join-Path $moduleRoot 'lib' 'PwSSH.Crypto.dll'
    $hashPath = Join-Path $moduleRoot 'lib' 'PwSSH.Crypto.dll.sha256'

    if (-not (Test-Path $dllPath)) {
        throw "pwssh: PwSSH.Crypto.dll not found at $dllPath. Run build.ps1 to compile the crypto assembly."
    }

    # Verify DLL integrity if hash file is present
    if (Test-Path $hashPath) {
        $expectedHash = ([System.IO.File]::ReadAllText($hashPath)).Trim().ToUpperInvariant()
        $actualHash = (Get-FileHash -Path $dllPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($expectedHash -ne $actualHash) {
            throw "pwssh: PwSSH.Crypto.dll integrity check FAILED. Expected SHA256: $expectedHash, Got: $actualHash. The assembly may have been tampered with."
        }
    }
    else {
        Write-Warning "pwssh: No integrity hash file found at $hashPath. PwSSH.Crypto.dll loaded without verification. Run build.ps1 to generate the hash file."
    }

    try {
        Add-Type -Path $dllPath -ErrorAction Stop
        Write-Verbose 'PwSSH.Crypto assembly loaded.'
    }
    catch [System.Reflection.ReflectionTypeLoadException] {
        # Assembly already loaded — safe to ignore
    }
    catch {
        throw "Failed to load PwSSH.Crypto: $_"
    }
}
