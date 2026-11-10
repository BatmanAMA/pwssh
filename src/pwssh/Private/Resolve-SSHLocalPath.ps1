function Resolve-SSHLocalPath {
    <#
    .SYNOPSIS
        Turns a PowerShell path (relative, ~, or absolute; need not exist) into a
        full file system path.
    .DESCRIPTION
        .NET file APIs resolve relative paths against the process working directory,
        which is not PowerShell's current location, and do not expand ~. Every local
        path handed to a .NET API must go through this function first.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}
