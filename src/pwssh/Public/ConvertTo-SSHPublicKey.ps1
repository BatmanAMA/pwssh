function ConvertTo-SSHPublicKey {
    <#
    .SYNOPSIS
        Extracts the public key from an OpenSSH private key file.
    .DESCRIPTION
        Reads an OpenSSH private key file and outputs the corresponding public key
        line (suitable for authorized_keys). Equivalent to ssh-keygen -y.
    .PARAMETER Path
        Path to the private key file.
    .PARAMETER Passphrase
        SecureString passphrase if the key is encrypted.
    .EXAMPLE
        ConvertTo-SSHPublicKey -Path ~/.ssh/id_ed25519
    .EXAMPLE
        $pass = Read-Host -AsSecureString
        ConvertTo-SSHPublicKey -Path ~/.ssh/id_rsa -Passphrase $pass
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

        if (-not (Test-Path $Path)) {
            Write-Error "Private key file not found: $Path"
            return
        }

        try {
            $pemText = [System.IO.File]::ReadAllText($Path)

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
                SourceFile    = (Resolve-Path $Path).Path
            }
        }
        catch {
            Write-Error "Failed to extract public key from '$Path': $_"
        }
    }
}
