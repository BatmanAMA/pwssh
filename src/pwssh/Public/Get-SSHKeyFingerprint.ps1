function Get-SSHKeyFingerprint {
    <#
    .SYNOPSIS
        Shows the fingerprint of an SSH key file.
    .DESCRIPTION
        Reads an SSH public or private key file and displays its fingerprint.
        Equivalent to ssh-keygen -l.
    .PARAMETER Path
        Path to a public key (.pub) or private key file.
    .PARAMETER Algorithm
        Hash algorithm for the fingerprint: SHA256 or MD5. Defaults to SHA256.
    .PARAMETER Passphrase
        SecureString passphrase if the private key is encrypted.
    .EXAMPLE
        Get-SSHKeyFingerprint -Path ~/.ssh/id_ed25519.pub
    .EXAMPLE
        Get-SSHKeyFingerprint -Path ~/.ssh/id_rsa -Algorithm MD5
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

        if (-not (Test-Path $Path)) {
            Write-Error "Key file not found: $Path"
            return
        }

        try {
            $content = [System.IO.File]::ReadAllText($Path).Trim()
            $keyData = $null

            if ($content.StartsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) {
                # Private key file
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
                $keyData = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($content, $passStr)
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
                SourceFile  = (Resolve-Path $Path).Path
            }
        }
        catch {
            Write-Error "Failed to read key file '$Path': $_"
        }
    }
}
