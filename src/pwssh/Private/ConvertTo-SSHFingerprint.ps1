function ConvertTo-SSHFingerprint {
    <#
    .SYNOPSIS
        Converts a raw host key byte array to SHA256 and MD5 fingerprint strings.
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
