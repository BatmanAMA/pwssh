function Receive-SCPFile {
    <#
    .SYNOPSIS
        Downloads a file from a remote host via SCP.
    .DESCRIPTION
        Copies a remote file to the local machine using SCP over an existing SSH session.
    .PARAMETER SessionId
        The session ID to use for the transfer.
    .PARAMETER Session
        An SSHSessionInfo object to use for the transfer.
    .PARAMETER RemotePath
        Path on the remote host to download.
    .PARAMETER LocalPath
        Local destination path.
    .PARAMETER Recurse
        Recursively download directories.
    .EXAMPLE
        Receive-SCPFile -SessionId 1 -RemotePath /var/log/syslog -LocalPath ./syslog.txt
    .EXAMPLE
        Receive-SCPFile -SessionId 1 -RemotePath /etc/nginx/ -LocalPath ./nginx-conf/ -Recurse
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [int]$SessionId,

        [Parameter(Mandatory, ParameterSetName = 'BySession', ValueFromPipeline)]
        [SSHSessionInfo]$Session,

        [Parameter(Mandatory, Position = 0)]
        [Alias('Source')]
        [string]$RemotePath,

        [Parameter(Mandatory, Position = 1)]
        [Alias('Destination', 'Path')]
        [string]$LocalPath,

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

        # Resolve and validate local path to prevent path traversal attacks
        $LocalPath = [System.IO.Path]::GetFullPath($LocalPath)

        try {
            $scpClient = Get-SSHScpClientInternal -SessionId $s.SessionId

            if ($Recurse) {
                $dirInfo = [System.IO.DirectoryInfo]::new($LocalPath)
                if (-not $dirInfo.Exists) { $dirInfo.Create() }
                $scpClient.Download($RemotePath, $dirInfo)
                Write-Verbose "Downloaded $($s.ComputerName):$RemotePath to $LocalPath"
            }
            else {
                $parentDir = Split-Path $LocalPath -Parent
                if ($parentDir -and -not (Test-Path $parentDir)) {
                    New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
                }
                $fileInfo = [System.IO.FileInfo]::new($LocalPath)
                $scpClient.Download($RemotePath, $fileInfo)
                Write-Verbose "Downloaded $($s.ComputerName):$RemotePath to $LocalPath"
            }
        }
        catch {
            Write-Error "SCP download failed: $_"
        }
    }
}
