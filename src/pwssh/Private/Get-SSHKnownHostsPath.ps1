function Get-SSHKnownHostsPath {
    <#
    .SYNOPSIS
        Returns the known_hosts file to use: the given path, or ~/.ssh/known_hosts.
    .DESCRIPTION
        Without -Path, ~/.ssh is created with owner-only permissions if it does
        not exist. The system-wide files are /etc/ssh/ssh_known_hosts and
        ssh_known_hosts2, or the same names under %ProgramData%\ssh on Windows.
    .PARAMETER Path
        An explicit known_hosts path (relative paths and ~ are resolved).
    .PARAMETER All
        Return every file that is consulted when verifying a host key, in order:
        the user files followed by the system-wide ones. With -Path, only that file.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,

        [switch]$All
    )

    if ($Path) { return (Resolve-SSHLocalPath -Path $Path) }

    $sshDir = Get-SSHUserDirectory -Create
    $userFile = Join-Path $sshDir 'known_hosts'
    if (-not $All) { return $userFile }

    $globalDir = if (Test-SSHIsWindows) {
        if ($env:ProgramData) { Join-Path $env:ProgramData 'ssh' } else { $null }
    }
    else { '/etc/ssh' }

    $paths = @($userFile, (Join-Path $sshDir 'known_hosts2'))
    if ($globalDir) {
        $paths += (Join-Path $globalDir 'ssh_known_hosts')
        $paths += (Join-Path $globalDir 'ssh_known_hosts2')
    }
    return $paths
}
