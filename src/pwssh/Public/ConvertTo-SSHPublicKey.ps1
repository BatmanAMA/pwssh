function ConvertTo-SSHPublicKey {
    <#
    .SYNOPSIS
        Extracts the public key from an OpenSSH private key file.
    .DESCRIPTION
        Reads a private key file and returns the corresponding public key line, in the
        form used in authorized_keys. Comparable to ssh-keygen -y.

        Only the OpenSSH private key format (-----BEGIN OPENSSH PRIVATE KEY-----) is
        read. PEM, PKCS#8 and PuTTY keys give an error. Encrypted keys need
        -Passphrase and must use aes256-ctr with bcrypt.
    .PARAMETER Path
        Path to the private key file. A relative path is resolved against the current
        PowerShell location and ~ is expanded. Accepts pipeline input. Aliases:
        PrivateKeyPath, FullName.
    .PARAMETER Passphrase
        SecureString passphrase if the key is encrypted.
    .EXAMPLE
        (ConvertTo-SSHPublicKey -Path ~/.ssh/id_ed25519).PublicKeyLine

        Prints the public key line of the key.
    .EXAMPLE
        $pass = Read-Host -AsSecureString -Prompt 'Passphrase'
        (ConvertTo-SSHPublicKey -Path ~/.ssh/id_rsa -Passphrase $pass).PublicKeyLine | Set-Content ~/.ssh/id_rsa.pub

        Recreates a lost .pub file from an encrypted private key.
    .OUTPUTS
        SSHPublicKeyInfo
        A custom object with KeyType, PublicKeyLine, Comment, Fingerprint (SHA256) and
        SourceFile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('PrivateKeyPath', 'FullName')]
        [string]$Path,

        [Parameter()]
        [securestring]$Passphrase
    )

    process {
        Initialize-SSHCrypto

        $fullPath = Resolve-SSHLocalPath -Path $Path
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            Write-Error "Private key file not found: $Path"
            return
        }

        try {
            $pemText = [System.IO.File]::ReadAllText($fullPath)

            $passStr = $null
            try {
                if ($Passphrase) {
                    $passStr = ConvertFrom-SecureStringPlain -SecureString $Passphrase
                }
                $keyData = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($pemText, $passStr)
            }
            finally {
                $passStr = $null
            }
            $pubLine = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPublicKeyLine($keyData)

            [PSCustomObject]@{
                PSTypeName    = 'SSHPublicKeyInfo'
                KeyType       = $keyData.KeyType
                PublicKeyLine = $pubLine
                Comment       = $keyData.Comment
                Fingerprint   = [PwSSH.Crypto.OpenSshKeyFormat]::Fingerprint($keyData.PublicKeyBlob, 'SHA256')
                SourceFile    = $fullPath
            }
        }
        catch {
            Write-Error "Failed to extract public key from '$Path': $(Get-SSHErrorMessage $_)"
        }
    }
}
