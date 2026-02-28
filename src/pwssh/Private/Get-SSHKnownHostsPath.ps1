function Get-SSHKnownHostsPath {
    <#
    .SYNOPSIS
        Returns the default known_hosts file path.
    #>
    [CmdletBinding()]
    param(
        [string]$Path
    )

    if ($Path) { return $Path }

    $sshDir = Join-Path $HOME '.ssh'
    if (-not (Test-Path $sshDir)) {
        New-Item -Path $sshDir -ItemType Directory -Force | Out-Null
    }
    return Join-Path $sshDir 'known_hosts'
}
