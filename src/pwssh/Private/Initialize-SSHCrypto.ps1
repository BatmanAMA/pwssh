function Initialize-SSHCrypto {
    <#
    .SYNOPSIS
        Compiles and loads the module's C# types (key handling, known_hosts,
        host key verification and the output classes). Idempotent.
    #>
    [CmdletBinding()]
    param()

    if (('PwSSH.Crypto.Ed25519' -as [type]) -and ('PwSSH.HostKeyVerifier' -as [type])) {
        Write-Verbose 'pwssh C# types already loaded.'
        return
    }

    $csDir = Join-Path $PSScriptRoot 'CSharp'
    $sources = @(
        (Join-Path $csDir 'SSHCrypto.cs')
        (Join-Path $csDir 'SSHTypes.cs')
    )
    foreach ($src in $sources) {
        if (-not (Test-Path -LiteralPath $src)) {
            throw "Cannot find $src"
        }
    }

    $params = @{
        LiteralPath = $sources
        ErrorAction = 'Stop'
    }

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        # .NET Framework: BigInteger and the CNG/ECC types live in separate assemblies.
        # (PowerShell 7 references the whole .NET reference set by default.)
        $params['ReferencedAssemblies'] = @('System.Numerics', 'System.Core')
    }

    try {
        Add-Type @params
        Write-Verbose 'pwssh C# types compiled and loaded.'
    }
    catch {
        throw "Failed to compile the pwssh C# types: $_"
    }
}
