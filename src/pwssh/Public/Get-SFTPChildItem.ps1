function Get-SFTPChildItem {
    <#
    .SYNOPSIS
        Lists files and directories on a remote host via SFTP.
    .DESCRIPTION
        Returns a listing of remote directory contents using SFTP, similar to Get-ChildItem.
    .PARAMETER SessionId
        The session ID to use.
    .PARAMETER Session
        An SSHSessionInfo object.
    .PARAMETER Path
        The remote directory path to list. Defaults to the user's home directory.
    .PARAMETER Recurse
        Recursively list subdirectories.
    .EXAMPLE
        Get-SFTPChildItem -SessionId 1 -Path /var/log
    .EXAMPLE
        Get-SFTPChildItem -SessionId 1 -Path /etc -Recurse
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [int]$SessionId,

        [Parameter(Mandatory, ParameterSetName = 'BySession', ValueFromPipeline)]
        [SSHSessionInfo]$Session,

        [Parameter(Position = 0)]
        [string]$Path = '.',

        [Parameter()]
        [switch]$Recurse
    )

    process {
        $s = switch ($PSCmdlet.ParameterSetName) {
            'ById' {
                Initialize-SSHSessionStore
                if ($script:SSHSessions.ContainsKey($SessionId)) { $script:SSHSessions[$SessionId] }
                else { Write-Error "Session $SessionId not found."; return }
            }
            'BySession' { $Session }
        }

        if (-not $s.Connected -or -not (Test-SSHClientConnected -SessionId $s.SessionId)) {
            Write-Error "Session $($s.SessionId) is not connected."
            return
        }

        try {
            $sftpClient = Get-SSHSftpClientInternal -SessionId $s.SessionId

            $listDir = {
                param($dirPath)
                $items = $sftpClient.ListDirectory($dirPath)
                foreach ($item in $items) {
                    if ($item.Name -eq '.' -or $item.Name -eq '..') { continue }
                    $item
                    if ($Recurse -and $item.IsDirectory) {
                        & $listDir $item.FullName
                    }
                }
            }

            & $listDir $Path
        }
        catch {
            Write-Error "SFTP listing failed: $_"
        }
    }
}
