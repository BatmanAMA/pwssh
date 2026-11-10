function New-SSHKeyPair {
    <#
    .SYNOPSIS
        Generates a new SSH key pair using pure .NET cryptography.
    .DESCRIPTION
        Creates a new SSH private/public key pair in OpenSSH format.
        Supports Ed25519, RSA, and ECDSA key types.
        No external tools (ssh-keygen) required.
    .PARAMETER Path
        Output path for the private key. The public key will be written to Path.pub.
    .PARAMETER KeyType
        The key algorithm: Ed25519, RSA, or ECDSA. Defaults to Ed25519.
    .PARAMETER KeySize
        Key size in bits (for RSA: 2048, 3072, 4096; for ECDSA: 256, 384, 521).
    .PARAMETER Comment
        Comment to embed in the public key. Defaults to user@hostname.
    .PARAMETER Passphrase
        SecureString passphrase to protect the private key.
    .PARAMETER Force
        Overwrite existing key files.
    .EXAMPLE
        New-SSHKeyPair -Path ~/.ssh/id_ed25519
    .EXAMPLE
        New-SSHKeyPair -Path ~/.ssh/id_rsa -KeyType RSA -KeySize 4096 -Comment 'deploy key'
    .EXAMPLE
        $pass = Read-Host -AsSecureString -Prompt 'Passphrase'
        New-SSHKeyPair -Path ~/.ssh/id_ed25519 -Passphrase $pass
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
                    Encrypted      = [bool]$Passphrase
                }
            }
            catch {
                Write-Error "Key generation failed: $(Get-SSHErrorMessage $_)"
            }
        }
    }
}
