function Receive-SFTPFile {
    <#
    .SYNOPSIS
        Downloads a file from a remote host via SFTP.
    .DESCRIPTION
        Copies a remote file to the local machine using SFTP.
    .PARAMETER SessionId
        The session ID to use for the transfer.
    .PARAMETER Session
        An SSHSessionInfo object to use for the transfer.
    .PARAMETER RemotePath
        Path on the remote host to download.
    .PARAMETER LocalPath
        Local destination path.
    .PARAMETER Overwrite
        Overwrite the local file if it exists.
    .EXAMPLE
        Receive-SFTPFile -SessionId 1 -RemotePath /var/log/app.log -LocalPath ./app.log
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
        [switch]$Overwrite
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

        if ((Test-Path $LocalPath) -and -not $Overwrite) {
            Write-Error "Local file '$LocalPath' already exists. Use -Overwrite to replace it."
            return
        }

        $parentDir = Split-Path $LocalPath -Parent
        if ($parentDir -and -not (Test-Path $parentDir)) {
            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        }

        try {
            $sftpClient = Get-SSHSftpClientInternal -SessionId $s.SessionId

            $stream = [System.IO.File]::Create($LocalPath)
            try {
                $sftpClient.DownloadFile($RemotePath, $stream)
                Write-Verbose "Downloaded $($s.ComputerName):$RemotePath to $LocalPath via SFTP"
            }
            finally {
                $stream.Dispose()
            }
        }
        catch {
            Write-Error "SFTP download failed: $_"
        }
    }
}
