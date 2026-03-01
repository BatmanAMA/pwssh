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
            $Path = Join-Path $HOME '.ssh' $keyName
        }

        $pubPath = "$Path.pub"

        if ((Test-Path $Path) -and -not $Force) {
            Write-Error "Key file '$Path' already exists. Use -Force to overwrite."
            return
        }

        if (-not $Comment) {
            $userName = if ($env:USER) { $env:USER } elseif ($env:USERNAME) { $env:USERNAME } else { 'user' }
            $Comment = "{0}@{1}" -f $userName, ([System.Net.Dns]::GetHostName())
        }

        $parentDir = Split-Path $Path -Parent
        if ($parentDir -and -not (Test-Path $parentDir)) {
            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        }

        if ($PSCmdlet.ShouldProcess($Path, "Generate $KeyType key")) {
            try {
                # Generate key data
                # Warn about non-constant-time Ed25519 on pre-.NET 9 runtimes
                if ($KeyType -eq 'Ed25519' -and [System.Environment]::Version.Major -lt 9) {
                    Write-Warning ("Ed25519 key generation uses non-constant-time arithmetic on this .NET version. " +
                        "For production keys on shared infrastructure, consider using ssh-keygen or upgrading to .NET 9+ (PowerShell 7.5+).")
                }
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
                $privContent = $null
                try {
                    if ($Passphrase) {
                        $passStr = ConvertFrom-SecureStringPlain -SecureString $Passphrase
                    }

                    # Write private key
                    $privContent = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPrivateKeyFile($keyData, $passStr)
                    [System.IO.File]::WriteAllText($Path, $privContent)
                }
                finally {
                    $passStr = $null
                    $privContent = $null   # Remove reference to PEM text with private key material
                }

                # Write public key
                $pubContent = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPublicKeyLine($keyData)
                [System.IO.File]::WriteAllText($pubPath, "$pubContent`n")

                # Set permissions
                if ($IsLinux -or $IsMacOS) {
                    & chmod 600 $Path 2>$null
                    & chmod 644 $pubPath 2>$null
                }
                elseif ($env:OS -eq 'Windows_NT' -or $PSVersionTable.Platform -eq 'Win32NT' -or (-not $IsLinux -and -not $IsMacOS)) {
                    # On Windows, restrict private key ACL to current user only
                    try {
                        $acl = Get-Acl -Path $Path
                        $acl.SetAccessRuleProtection($true, $false)
                        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                            $currentUser,
                            [System.Security.AccessControl.FileSystemRights]::FullControl,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                        $acl.SetAccessRule($rule)
                        Set-Acl -Path $Path -AclObject $acl
                    }
                    catch {
                        Write-Warning "Could not restrict private key file permissions on Windows: $_"
                    }
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
                Write-Error "Key generation failed: $_"
            }
        }
    }
}
