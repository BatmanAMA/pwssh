function Get-SSHAuthMethod {
    <#
    .SYNOPSIS
        Builds Renci.SshNet authentication method objects from supplied credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserName,

        [pscredential]$Credential,

        [string]$KeyFile,

        [securestring]$KeyPassphrase
    )

    $methods = [System.Collections.Generic.List[object]]::new()

    # Key-based auth
    if ($KeyFile) {
        $resolvedKey = Resolve-Path -Path $KeyFile -ErrorAction Stop
        if ($KeyPassphrase) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeyPassphrase)
            try {
                $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                $pkFile = [Renci.SshNet.PrivateKeyFile]::new($resolvedKey.Path, $plain)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
        else {
            $pkFile = [Renci.SshNet.PrivateKeyFile]::new($resolvedKey.Path)
        }
        $methods.Add([Renci.SshNet.PrivateKeyAuthenticationMethod]::new($UserName, $pkFile))
    }

    # Password auth
    if ($Credential) {
        $networkCred = $Credential.GetNetworkCredential()
        $methods.Add([Renci.SshNet.PasswordAuthenticationMethod]::new($networkCred.UserName, $networkCred.Password))
    }

    if ($methods.Count -eq 0) {
        # Try default key locations
        $defaultKeys = @(
            (Join-Path $HOME '.ssh' 'id_ed25519'),
            (Join-Path $HOME '.ssh' 'id_rsa'),
            (Join-Path $HOME '.ssh' 'id_ecdsa')
        )
        foreach ($dk in $defaultKeys) {
            if (Test-Path $dk) {
                try {
                    $pkFile = [Renci.SshNet.PrivateKeyFile]::new($dk)
                    $methods.Add([Renci.SshNet.PrivateKeyAuthenticationMethod]::new($UserName, $pkFile))
                    break
                }
                catch {
                    # Key might need passphrase — skip
                }
            }
        }
    }

    return $methods
}
