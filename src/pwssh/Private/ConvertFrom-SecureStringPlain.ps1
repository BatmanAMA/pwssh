function ConvertFrom-SecureStringPlain {
    <#
    .SYNOPSIS
        Converts a SecureString to a plain string, clearing the reference after use.
    .DESCRIPTION
        Returns a plain string from a SecureString. The BSTR is zeroed immediately.
        The caller MUST null the returned string variable when done to remove the
        managed reference. .NET strings are immutable and cannot be pinned/zeroed;
        this is a known limitation documented here for security-conscious users.
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
