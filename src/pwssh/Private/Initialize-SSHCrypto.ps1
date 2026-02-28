function Initialize-SSHCrypto {
    <#
    .SYNOPSIS
        Loads the PwSSH.Crypto C# types via Add-Type.
        Idempotent — skips if already loaded.
    #>
    [CmdletBinding()]
    param()

    if ([System.Management.Automation.PSTypeName]'PwSSH.Crypto.Ed25519' -as [type]) {
        Write-Verbose 'PwSSH.Crypto types already loaded.'
        return
    }

    $csPath = Join-Path $PSScriptRoot 'CSharp' 'SSHCrypto.cs'
    if (-not (Test-Path $csPath)) {
        throw "Cannot find SSHCrypto.cs at $csPath"
    }

    $csSource = [System.IO.File]::ReadAllText($csPath)

    # Build referenced assemblies list (differs between Desktop and Core)
    $refs = [System.Collections.Generic.List[string]]::new()

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        # .NET Framework — need explicit reference to System.Numerics.dll
        $refs.Add('System.Numerics')
    }
    else {
        # .NET Core / .NET 5+ — find System.Runtime.Numerics assembly
        $numAssembly = [System.Numerics.BigInteger].Assembly.Location
        if ($numAssembly) { $refs.Add($numAssembly) }

        # Also need System.Security.Cryptography assemblies
        $cryptoAssemblies = @(
            [System.Security.Cryptography.SHA512].Assembly.Location,
            [System.Security.Cryptography.RSA].Assembly.Location,
            [System.Security.Cryptography.ECDsa].Assembly.Location,
            [System.Security.Cryptography.Aes].Assembly.Location,
            [System.Security.Cryptography.RandomNumberGenerator].Assembly.Location
        ) | Where-Object { $_ } | Select-Object -Unique

        foreach ($a in $cryptoAssemblies) {
            $refs.Add($a)
        }
    }

    $params = @{
        TypeDefinition       = $csSource
        Language              = 'CSharp'
        ErrorAction           = 'Stop'
    }

    if ($refs.Count -gt 0) {
        $params['ReferencedAssemblies'] = $refs.ToArray()
    }

    try {
        Add-Type @params
        Write-Verbose 'PwSSH.Crypto types compiled and loaded.'
    }
    catch {
        throw "Failed to compile PwSSH.Crypto: $_"
    }
}
