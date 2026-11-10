function Get-SSHKeyFingerprint {
    <#
    .SYNOPSIS
        Shows the fingerprint of an SSH key file.
    .DESCRIPTION
        Reads an OpenSSH public key file or an OpenSSH private key file and returns
        the fingerprint of the public key. Comparable to ssh-keygen -l.

        A file that starts with -----BEGIN OPENSSH PRIVATE KEY----- is read as a
        private key; anything else is read as a public key line. PEM, PKCS#8 and PuTTY
        private keys give an error. An encrypted private key needs -Passphrase; the
        matching .pub file does not.
    .PARAMETER Path
        Path to a public key (.pub) or private key file. A relative path is resolved
        against the current PowerShell location and ~ is expanded. Accepts pipeline
        input, including file objects from Get-ChildItem (alias FullName).
    .PARAMETER Algorithm
        Hash algorithm for the fingerprint: SHA256 or MD5. Defaults to SHA256.
    .PARAMETER Passphrase
        SecureString passphrase if the private key is encrypted.
    .EXAMPLE
        Get-SSHKeyFingerprint -Path ~/.ssh/id_ed25519.pub
    .EXAMPLE
        Get-SSHKeyFingerprint -Path ~/.ssh/id_rsa -Algorithm MD5

        Shows the fingerprint in the older colon-separated MD5 form.
    .EXAMPLE
        Get-ChildItem ~/.ssh/*.pub | Get-SSHKeyFingerprint

        Lists the fingerprints of all public keys in ~/.ssh.
    .OUTPUTS
        SSHKeyFingerprintInfo
        A custom object with KeyBits, Fingerprint, Comment, KeyType and SourceFile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string]$Path,

        [Parameter()]
        [ValidateSet('SHA256', 'MD5')]
        [string]$Algorithm = 'SHA256',

        [Parameter()]
        [securestring]$Passphrase
    )

    process {
        Initialize-SSHCrypto

        $fullPath = Resolve-SSHLocalPath -Path $Path
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            Write-Error "Key file not found: $Path"
            return
        }

        try {
            $content = [System.IO.File]::ReadAllText($fullPath).Trim()
            $keyData = $null

            if ($content.StartsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) {
                # Private key file
                $passStr = $null
                try {
                    if ($Passphrase) {
                        $passStr = ConvertFrom-SecureStringPlain -SecureString $Passphrase
                    }
                    $keyData = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($content, $passStr)
                }
                finally {
                    $passStr = $null
                }
            }
            else {
                # Public key line
                $keyData = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePublicKeyLine($content)
            }

            $fp = [PwSSH.Crypto.OpenSshKeyFormat]::Fingerprint($keyData.PublicKeyBlob, $Algorithm)

            # Determine key size for display
            $keyBits = switch -Wildcard ($keyData.KeyType) {
                'ssh-ed25519'        { 256 }
                'ssh-rsa'            { $keyData.RsaParameters.Modulus.Length * 8 }
                'ecdsa-sha2-nistp256' { 256 }
                'ecdsa-sha2-nistp384' { 384 }
                'ecdsa-sha2-nistp521' { 521 }
                default              { 0 }
            }

            [PSCustomObject]@{
                PSTypeName  = 'SSHKeyFingerprintInfo'
                KeyBits     = $keyBits
                Fingerprint = $fp
                Comment     = $keyData.Comment
                KeyType     = $keyData.KeyType
                SourceFile  = $fullPath
            }
        }
        catch {
            Write-Error "Failed to read key file '$Path': $(Get-SSHErrorMessage $_)"
        }
    }
}
