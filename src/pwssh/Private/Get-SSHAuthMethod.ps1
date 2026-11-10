function Get-SSHAuthMethod {
    <#
    .SYNOPSIS
        Builds the Renci.SshNet authentication methods for a connection.
    .DESCRIPTION
        Order of preference:
          1. -KeyFile (must load; a wrong or missing passphrase is an error)
          2. -Credential, offered both as "password" and as "keyboard-interactive"
             (many servers only enable the latter)
          3. With neither: -IdentityFile candidates (from ~/.ssh/config) followed by
             the default keys ~/.ssh/id_ed25519, id_ecdsa, id_rsa. Keys that cannot
             be loaded (for example because they are passphrase-protected) are skipped.
    .OUTPUTS
        PSCustomObject with Methods (object[]), Description (string) and
        SendsPassword (bool).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserName,

        [pscredential]$Credential,

        [string]$KeyFile,

        [securestring]$KeyPassphrase,

        [string[]]$IdentityFile
    )

    $methods = [System.Collections.Generic.List[object]]::new()
    $kinds = [System.Collections.Generic.List[string]]::new()
    $sendsPassword = $false

    # Explicit key
    if ($KeyFile) {
        $keyPath = Resolve-SSHLocalPath -Path $KeyFile
        if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
            throw "Private key file not found: $KeyFile"
        }
        if ($KeyPassphrase) {
            $plain = ConvertFrom-SecureStringPlain -SecureString $KeyPassphrase
            try { $pkFile = [Renci.SshNet.PrivateKeyFile]::new($keyPath, $plain) }
            finally { $plain = $null }
        }
        else {
            $pkFile = [Renci.SshNet.PrivateKeyFile]::new($keyPath)
        }
        $methods.Add([Renci.SshNet.PrivateKeyAuthenticationMethod]::new($UserName, $pkFile))
        $kinds.Add('PublicKey')
    }

    # Password, also offered through keyboard-interactive
    if ($Credential) {
        $password = $Credential.GetNetworkCredential().Password
        $methods.Add([Renci.SshNet.PasswordAuthenticationMethod]::new($UserName, $password))

        $kbd = [Renci.SshNet.KeyboardInteractiveAuthenticationMethod]::new($UserName)
        [PwSSH.KeyboardInteractiveResponder]::new($password).Attach($kbd)
        $methods.Add($kbd)

        $password = $null
        $kinds.Add('Password')
        $sendsPassword = $true
    }

    # Nothing explicit: configured identities, then the default key files
    if ($methods.Count -eq 0) {
        $sshDir = Get-SSHUserDirectory
        $candidates = @($IdentityFile | Where-Object { $_ } | ForEach-Object { Resolve-SSHLocalPath -Path $_ })
        $candidates += @('id_ed25519', 'id_ecdsa', 'id_rsa') | ForEach-Object { Join-Path $sshDir $_ }

        $keys = [System.Collections.Generic.List[object]]::new()
        $seen = @{}
        foreach ($candidate in $candidates) {
            if ($seen.ContainsKey($candidate)) { continue }
            $seen[$candidate] = $true
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
            try {
                $keys.Add([Renci.SshNet.PrivateKeyFile]::new($candidate))
                Write-Verbose "Offering identity $candidate"
            }
            catch {
                Write-Verbose "Skipping identity $candidate (passphrase-protected or unreadable): $($_.Exception.Message)"
            }
        }
        if ($keys.Count -gt 0) {
            $keyArray = [Renci.SshNet.PrivateKeyFile[]]$keys.ToArray()
            $methods.Add([Renci.SshNet.PrivateKeyAuthenticationMethod]::new($UserName, $keyArray))
            $kinds.Add('PublicKey')
        }
    }

    [PSCustomObject]@{
        Methods       = $methods.ToArray()
        Description   = ($kinds -join ',')
        SendsPassword = $sendsPassword
    }
}
