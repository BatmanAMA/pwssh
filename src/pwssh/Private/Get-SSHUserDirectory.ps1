function Get-SSHUserDirectory {
    <#
    .SYNOPSIS
        Returns ~/.ssh, optionally creating it with owner-only permissions.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [switch]$Create
    )

    $sshDir = Join-Path $HOME '.ssh'
    if ($Create -and -not (Test-Path -LiteralPath $sshDir)) {
        New-Item -Path $sshDir -ItemType Directory -Force | Out-Null
        try { Set-SSHPrivatePermission -LiteralPath $sshDir }
        catch { Write-Warning $_.Exception.Message }
    }
    return $sshDir
}
