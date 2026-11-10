function ConvertFrom-SecureStringPlain {
    <#
    .SYNOPSIS
        Converts a SecureString to a plain string.
    .DESCRIPTION
        Returns the content of a SecureString as a plain string. The intermediate
        unmanaged copy (BSTR) is zeroed and freed before the function returns.
        The returned string itself cannot be cleared, because managed strings are
        immutable. Callers set their variable to $null when done so that the
        string is no longer referenced; it stays in memory until it is garbage
        collected.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [securestring]$SecureString
    )

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}
