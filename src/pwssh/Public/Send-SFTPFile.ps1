function Send-SFTPFile {
    <#
    .SYNOPSIS
        Uploads a file to a remote host via SFTP.
    .DESCRIPTION
        Copies a local file to the remote host using SFTP, which provides better
        error handling and progress tracking than SCP.
    .PARAMETER SessionId
        The session ID to use for the transfer.
    .PARAMETER Session
        An SSHSessionInfo object to use for the transfer.
    .PARAMETER LocalPath
        Path to the local file to upload.
    .PARAMETER RemotePath
        Destination path on the remote host.
    .PARAMETER Overwrite
        Overwrite the remote file if it exists.
    .EXAMPLE
        Send-SFTPFile -SessionId 1 -LocalPath ./config.yml -RemotePath /etc/myapp/config.yml
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [int]$SessionId,

        [Parameter(Mandatory, ParameterSetName = 'BySession', ValueFromPipeline)]
        [SSHSessionInfo]$Session,

        [Parameter(Mandatory, Position = 0)]
        [Alias('Source', 'Path')]
        [string]$LocalPath,

        [Parameter(Mandatory, Position = 1)]
        [Alias('Destination')]
        [string]$RemotePath,

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

        $resolvedPath = Resolve-Path -Path $LocalPath -ErrorAction Stop

        try {
            $sftpClient = Get-SSHSftpClientInternal -SessionId $s.SessionId

            $stream = [System.IO.File]::OpenRead($resolvedPath.Path)
            try {
                $sftpClient.UploadFile($stream, $RemotePath, $Overwrite.IsPresent)
                Write-Verbose "Uploaded $resolvedPath to $($s.ComputerName):$RemotePath via SFTP"
            }
            finally {
                $stream.Dispose()
            }
        }
        catch {
            Write-Error "SFTP upload failed: $_"
        }
    }
}
