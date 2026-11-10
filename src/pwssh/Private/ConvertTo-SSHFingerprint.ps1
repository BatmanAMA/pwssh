function ConvertTo-SSHFingerprint {
    <#
    .SYNOPSIS
        Returns the SHA256 or MD5 fingerprint string of a public key blob.
    .DESCRIPTION
        SHA256 fingerprints are returned as "SHA256:" followed by unpadded base64,
        MD5 fingerprints as "MD5:" followed by colon-separated hex bytes, as
        OpenSSH prints them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$KeyData,

        [ValidateSet('SHA256', 'MD5')]
        [string]$Algorithm = 'SHA256'
    )

    switch ($Algorithm) {
        'SHA256' {
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $hash = $sha256.ComputeHash($KeyData)
            $sha256.Dispose()
            return "SHA256:" + [System.Convert]::ToBase64String($hash).TrimEnd('=')
        }
        'MD5' {
            $md5 = [System.Security.Cryptography.MD5]::Create()
            $hash = $md5.ComputeHash($KeyData)
            $md5.Dispose()
            return "MD5:" + (($hash | ForEach-Object { $_.ToString('x2') }) -join ':')
        }
    }
}
