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

        if (-not (Test-Path $Path)) {
            $result.Error = 'File not found'
            $result
            return
        }

        try {
            $content = [System.IO.File]::ReadAllText($Path).Trim()

            if ($content.StartsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) {
                $result.Format = 'OpenSSH Private Key'

                # Check if encrypted by peeking at the binary
                $b64 = $content.
                    Replace('-----BEGIN OPENSSH PRIVATE KEY-----', '').
                    Replace('-----END OPENSSH PRIVATE KEY-----', '').
                    Replace("`r", '').Replace("`n", '').Trim()
                $raw = [System.Convert]::FromBase64String($b64)
                $magic = [System.Text.Encoding]::ASCII.GetString($raw, 0, 14)

                if ($magic -eq 'openssh-key-v1') {
                    # Read cipher name to check encryption
                    $ms = [System.IO.MemoryStream]::new($raw)
                    $ms.Position = 15 # skip magic + null
                    $cipherName = [PwSSH.Crypto.SshWireFormat]::ReadString($ms)
                    $ms.Dispose()
                    $result.Encrypted = ($cipherName -ne 'none')
                }

                $passStr = $null
                if ($Passphrase) {
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase)
                    try {
                        $passStr = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                    }
                    finally {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    }
                }

                if ($result.Encrypted -and -not $passStr) {
                    $result.Error = 'Key is encrypted; provide -Passphrase to fully validate'
                    $result.Valid = $false
                    # Still report what we can
                    $result
                    return
                }

                $keyData = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($content, $passStr)
                $result.KeyType = $keyData.KeyType
                $result.Valid = $true
            }
            elseif ($content -match '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+)\s+\S+') {
                $result.Format = 'OpenSSH Public Key'
                $keyData = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePublicKeyLine($content)
                $result.KeyType = $keyData.KeyType
                $result.Valid = $true
            }
            else {
                $result.Error = 'Unrecognized key format'
            }
        }
        catch {
            $result.Error = $_.Exception.Message
        }

        $result
    }
}
