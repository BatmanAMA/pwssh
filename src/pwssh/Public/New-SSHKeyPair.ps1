function New-SSHKeyPair {
    <#
    .SYNOPSIS
        Generates a new SSH key pair in OpenSSH format.
    .DESCRIPTION
        Creates a private key file in the OpenSSH private key format and the matching
        public key file (the same path with .pub appended). The keys are generated
        with .NET cryptography; ssh-keygen is not needed. OpenSSH can read the files.

        Key types:
        - Ed25519 (default)
        - RSA, 2048 to 16384 bits in multiples of 8, default 4096
        - ECDSA with the NIST curves P-256 (default), P-384 and P-521

        With -Passphrase the private key is encrypted with aes256-ctr, using a key
        derived with bcrypt_pbkdf (16 rounds). Without it the private key is stored
        unencrypted.

        The private key file is created empty, restricted to the current user (mode
        0600, or an owner-only ACL on Windows) and only then written, so the key is
        never readable by other users. If the permissions cannot be applied the file is
        removed and the command fails. A missing parent directory is created with
        owner-only permissions. Supports -WhatIf and -Confirm.
    .PARAMETER Path
        Output path for the private key. The public key is written to the same path
        with .pub appended. Defaults to ~/.ssh/id_ed25519, id_rsa or id_ecdsa depending
        on -KeyType. A relative path is resolved against the current PowerShell
        location and ~ is expanded.
    .PARAMETER KeyType
        The key algorithm: Ed25519, RSA or ECDSA. Defaults to Ed25519.
    .PARAMETER KeySize
        Key size in bits. For RSA: a multiple of 8 from 2048 to 16384, default 4096.
        For ECDSA: 256, 384 or 521, default 256. Ed25519 keys have a fixed size, so
        omit this parameter for them.
    .PARAMETER Comment
        Comment stored with the key. Defaults to user@hostname.
    .PARAMETER Passphrase
        SecureString passphrase to encrypt the private key with.
    .PARAMETER Force
        Replace an existing private key file. Without it the command writes an error
        if the file exists. The public key file is always replaced.
    .EXAMPLE
        New-SSHKeyPair -Path ~/.ssh/id_ed25519

        Creates an unencrypted Ed25519 key pair.
    .EXAMPLE
        New-SSHKeyPair -Path ~/.ssh/id_rsa -KeyType RSA -KeySize 4096 -Comment 'deploy key'
    .EXAMPLE
        $pass = Read-Host -AsSecureString -Prompt 'Passphrase'
        New-SSHKeyPair -Path ./keys/id_ecdsa -KeyType ECDSA -KeySize 384 -Passphrase $pass

        Creates a passphrase-protected ECDSA P-384 key pair below the current location.
    .OUTPUTS
        SSHKeyPairInfo
        A custom object with PrivateKeyPath, PublicKeyPath, KeyType, Fingerprint
        (SHA256), Comment and Encrypted.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Position = 0)]
        [string]$Path,

        [Parameter()]
        [ValidateSet('Ed25519', 'RSA', 'ECDSA')]
        [string]$KeyType = 'Ed25519',

        [Parameter()]
        [int]$KeySize,

        [Parameter()]
        [string]$Comment,

        [Parameter()]
        [securestring]$Passphrase,

        [Parameter()]
        [switch]$Force
    )

    process {
        Initialize-SSHCrypto

        # Default path
        if (-not $Path) {
            $keyName = switch ($KeyType) {
                'Ed25519' { 'id_ed25519' }
                'RSA'     { 'id_rsa' }
                'ECDSA'   { 'id_ecdsa' }
            }
            $Path = Join-Path (Get-SSHUserDirectory) $keyName
        }

        # .NET resolves relative paths against the process directory, not $PWD
        $Path = Resolve-SSHLocalPath -Path $Path
        $pubPath = "$Path.pub"

        if ($KeyType -eq 'RSA' -and $KeySize -and ($KeySize -lt 2048 -or $KeySize -gt 16384 -or $KeySize % 8)) {
            Write-Error 'RSA key size must be a multiple of 8 between 2048 and 16384 bits.'
            return
        }
        if ($KeyType -eq 'ECDSA' -and $KeySize -and $KeySize -notin 256, 384, 521) {
            Write-Error 'ECDSA key size must be 256, 384 or 521.'
            return
        }
        if ($KeyType -eq 'Ed25519' -and $KeySize -and $KeySize -ne 256) {
            Write-Error 'Ed25519 keys have a fixed size; omit -KeySize.'
            return
        }

        if ((Test-Path -LiteralPath $Path) -and -not $Force) {
            Write-Error "Key file '$Path' already exists. Use -Force to overwrite."
            return
        }

        if (-not $Comment) {
            $userName = if ($env:USER) { $env:USER } elseif ($env:USERNAME) { $env:USERNAME } else { 'user' }
            $Comment = "{0}@{1}" -f $userName, ([System.Net.Dns]::GetHostName())
        }

        if ($PSCmdlet.ShouldProcess($Path, "Generate $KeyType key")) {
            try {
                $parentDir = Split-Path $Path -Parent
                if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
                    New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
                    Set-SSHPrivatePermission -LiteralPath $parentDir
                }

                # Generate key data
                $keyData = switch ($KeyType) {
                    'Ed25519' {
                        [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519($Comment)
                    }
                    'RSA' {
                        $bits = if ($KeySize) { $KeySize } else { 4096 }
                        [PwSSH.Crypto.OpenSshKeyFormat]::GenerateRsa($bits, $Comment)
                    }
                    'ECDSA' {
                        $bits = if ($KeySize) { $KeySize } else { 256 }
                        [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEcdsa($bits, $Comment)
                    }
                }

                $passStr = $null
                try {
                    if ($Passphrase) {
                        $passStr = ConvertFrom-SecureStringPlain -SecureString $Passphrase
                    }

                    # Write private key
                    $privContent = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPrivateKeyFile($keyData, $passStr)
                }
                finally {
                    $passStr = $null
                }
                # Create the private key file empty, restrict it, and only then write the
                # key, so it is never readable by anyone else. Removing an existing file
                # first also stops us writing through a symlink or inheriting loose
                # permissions.
                if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
                [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew).Dispose()
                try {
                    Set-SSHPrivatePermission -LiteralPath $Path
                    [System.IO.File]::WriteAllText($Path, $privContent, [System.Text.UTF8Encoding]::new($false))
                }
                catch {
                    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
                    throw
                }
                finally {
                    $privContent = $null
                }

                # Write public key
                $pubContent = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPublicKeyLine($keyData)
                [System.IO.File]::WriteAllText($pubPath, "$pubContent`n", [System.Text.UTF8Encoding]::new($false))
                if (-not (Test-SSHIsWindows)) {
                    & chmod 644 $pubPath 2>$null
                }

                # Calculate fingerprint
                $fp = [PwSSH.Crypto.OpenSshKeyFormat]::Fingerprint($keyData.PublicKeyBlob, 'SHA256')

                Write-Verbose "Generated $KeyType key pair at $Path"

                [PSCustomObject]@{
                    PSTypeName     = 'SSHKeyPairInfo'
                    PrivateKeyPath = $Path
                    PublicKeyPath  = $pubPath
                    KeyType        = $KeyType
                    Fingerprint    = $fp
                    Comment        = $Comment
                    Encrypted      = [bool]($Passphrase -and $Passphrase.Length -gt 0)
                }
            }
            catch {
                Write-Error "Key generation failed: $(Get-SSHErrorMessage $_)"
            }
        }
    }
}
