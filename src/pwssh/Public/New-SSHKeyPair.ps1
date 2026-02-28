function New-SSHKeyPair {
    <#
    .SYNOPSIS
        Generates a new SSH key pair.
    .DESCRIPTION
        Creates a new SSH private/public key pair using ssh-keygen.
        Supports Ed25519, RSA, and ECDSA key types.
        Works on Windows PowerShell 5.1 and PowerShell 7.x.
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
                $keygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
                if (-not $keygen) {
                    throw "ssh-keygen not found. Install OpenSSH to generate keys."
                }

                # Build ssh-keygen arguments
                $sshKeyType = switch ($KeyType) {
                    'Ed25519' { 'ed25519' }
                    'RSA'     { 'rsa' }
                    'ECDSA'   { 'ecdsa' }
                }

                $passArg = ''
                if ($Passphrase) {
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase)
                    try { $passArg = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
                    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
                }

                if (Test-Path $Path) { Remove-Item $Path -Force }
                if (Test-Path $pubPath) { Remove-Item $pubPath -Force }

                $keygenArgs = @('-t', $sshKeyType, '-f', $Path, '-C', $Comment, '-N', $passArg)

                # Add key size for RSA and ECDSA
                if ($KeyType -eq 'RSA') {
                    $bits = if ($KeySize) { $KeySize } else { 4096 }
                    $keygenArgs += @('-b', $bits.ToString())
                }
                elseif ($KeyType -eq 'ECDSA' -and $KeySize) {
                    $keygenArgs += @('-b', $KeySize.ToString())
                }

                $output = & ssh-keygen @keygenArgs 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "ssh-keygen failed: $output"
                }

                # Set permissions (Unix-like)
                if ($IsLinux -or $IsMacOS) {
                    & chmod 600 $Path 2>$null
                    & chmod 644 $pubPath 2>$null
                }

                Write-Verbose "Generated $KeyType key pair at $Path"

                [PSCustomObject]@{
                    PrivateKeyPath = $Path
                    PublicKeyPath  = $pubPath
                    KeyType        = $KeyType
                    Comment        = $Comment
                }
            }
            catch {
                Write-Error "Key generation failed: $_"
            }
        }
    }
}
