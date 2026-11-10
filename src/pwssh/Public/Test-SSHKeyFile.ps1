function Test-SSHKeyFile {
    <#
    .SYNOPSIS
        Validates an SSH key file.
    .DESCRIPTION
        Tests whether a file is a valid OpenSSH key (public or private).
        Returns a validation result object. Equivalent to ssh-keygen -y (for validation).
    .PARAMETER Path
        Path to the key file to validate.
    .PARAMETER Passphrase
        SecureString passphrase if the private key is encrypted.
    .EXAMPLE
        Test-SSHKeyFile -Path ~/.ssh/id_ed25519
    .EXAMPLE
        Get-ChildItem ~/.ssh/id_* | Test-SSHKeyFile
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string]$Path,

        [Parameter()]
        [securestring]$Passphrase
    )

    process {
        Initialize-SSHCrypto

        $result = [PSCustomObject]@{
            PSTypeName = 'SSHKeyValidationResult'
            Path       = $Path
            Valid      = $false
            KeyType    = $null
            Format     = $null
            Encrypted  = $false
            Error      = $null
        }

        $fullPath = Resolve-SSHLocalPath -Path $Path
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            $result.Error = 'File not found'
            $result
            return
        }

        try {
            $content = [System.IO.File]::ReadAllText($fullPath).Trim()

            if ($content.StartsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) {
                $result.Format = 'OpenSSH Private Key'

                $cipherName = [PwSSH.Crypto.OpenSshKeyFormat]::GetCipherName($content)
                $result.Encrypted = ($cipherName -ne 'none')

                $passStr = $null
                try {
                    if ($Passphrase) {
                        $passStr = ConvertFrom-SecureStringPlain -SecureString $Passphrase
                    }

                    if ($result.Encrypted -and -not $passStr) {
                        $result.Error = 'Key is encrypted; provide -Passphrase to fully validate'
                        $result.Valid = $false
                        $result
                        return
                    }

                    $keyData = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($content, $passStr)
                }
                finally {
                    $passStr = $null
                }
                $result.KeyType = $keyData.KeyType
                $result.Valid = $true
            }
            elseif ($content -match '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+)\s+\S+') {
                $result.Format = 'OpenSSH Public Key'
                $keyData = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePublicKeyLine($content)
                $result.KeyType = $keyData.KeyType
                $result.Valid = $true
            }
            elseif ($content -match '^-----BEGIN ((RSA|EC|DSA|ENCRYPTED) )?PRIVATE KEY-----') {
                $result.Format = 'PEM Private Key'
                $result.Error = 'PEM/PKCS#8 private keys are not parsed by this cmdlet. Convert with: ssh-keygen -p -f <file>'
            }
            elseif ($content.StartsWith('PuTTY-User-Key-File')) {
                $result.Format = 'PuTTY Private Key'
                $result.Error = 'PuTTY .ppk keys are not supported. Export the key in OpenSSH format from PuTTYgen.'
            }
            else {
                $result.Error = 'Unrecognized key format'
            }
        }
        catch {
            $result.Error = Get-SSHErrorMessage $_
        }

        $result
    }
}
