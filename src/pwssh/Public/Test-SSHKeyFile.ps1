function Test-SSHKeyFile {
    <#
    .SYNOPSIS
        Checks whether a file is a valid OpenSSH key.
    .DESCRIPTION
        Reads a key file and reports whether it could be parsed. Two formats are
        parsed: OpenSSH private keys (files that start with
        -----BEGIN OPENSSH PRIVATE KEY-----) and OpenSSH public key lines of type
        ssh-ed25519, ssh-rsa or ecdsa-sha2-*.

        PEM and PKCS#8 private keys and PuTTY .ppk files are recognised but not parsed:
        they are reported as not valid, with an explanation in the Error property.

        An encrypted private key can only be validated with its passphrase. Without
        -Passphrase it is reported as encrypted and not valid. Only keys encrypted with
        aes256-ctr and bcrypt can be decrypted.

        A missing file, a wrong passphrase or a damaged key does not produce an error.
        The command returns a result with Valid set to false and the reason in Error.
    .PARAMETER Path
        Path to the key file to check. A relative path is resolved against the current
        PowerShell location and ~ is expanded. Accepts pipeline input, including file
        objects from Get-ChildItem (alias FullName).
    .PARAMETER Passphrase
        SecureString passphrase for an encrypted private key.
    .EXAMPLE
        Test-SSHKeyFile -Path ~/.ssh/id_ed25519
    .EXAMPLE
        Get-ChildItem ~/.ssh/id_* | Test-SSHKeyFile | Where-Object { -not $_.Valid }

        Shows the key files in ~/.ssh that could not be validated, and why.
    .EXAMPLE
        $pass = Read-Host -AsSecureString -Prompt 'Passphrase'
        (Test-SSHKeyFile -Path ./deploy_key -Passphrase $pass).Valid

        Checks that the passphrase opens the key.
    .OUTPUTS
        SSHKeyValidationResult
        A custom object with Path, Valid, KeyType, Format, Encrypted and Error.
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
