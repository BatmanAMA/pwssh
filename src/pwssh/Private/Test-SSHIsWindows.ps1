function Test-SSHIsWindows {
    <#
    .SYNOPSIS
        True on Windows, including Windows PowerShell 5.1 where $IsWindows does not exist.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($PSVersionTable.PSEdition -eq 'Desktop') { return $true }
    return [bool]$IsWindows
}
