function Send-SCPFile {
    <#
    .SYNOPSIS
        Uploads a file to a remote host via SCP.
    .DESCRIPTION
        Copies a local file to the remote host using the SCP protocol over an existing SSH session.
    .PARAMETER SessionId
        The session ID to use for the transfer.
    .PARAMETER Session
        An SSHSessionInfo object to use for the transfer.
    .PARAMETER LocalPath
        Path to the local file or directory to upload.
    .PARAMETER RemotePath
        Destination path on the remote host.
    .PARAMETER Recurse
        Recursively upload directories.
    .EXAMPLE
        Send-SCPFile -SessionId 1 -LocalPath ./app.tar.gz -RemotePath /tmp/app.tar.gz
    .EXAMPLE
        Send-SCPFile -SessionId 1 -LocalPath ./deploy/ -RemotePath /opt/app/ -Recurse
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

        $resolvedPath = Resolve-Path -Path $LocalPath -ErrorAction Stop

        try {
            $scpClient = Get-SSHScpClientInternal -SessionId $s.SessionId

            if (Test-Path $resolvedPath -PathType Container) {
                if (-not $Recurse) {
                    Write-Error "Source is a directory. Use -Recurse to upload directories."
                    return
                }
                $dirInfo = [System.IO.DirectoryInfo]::new($resolvedPath.Path)
                $scpClient.Upload($dirInfo, $RemotePath)
                Write-Verbose "Uploaded directory $resolvedPath to $($s.ComputerName):$RemotePath"
            }
            else {
                $fileInfo = [System.IO.FileInfo]::new($resolvedPath.Path)
                $scpClient.Upload($fileInfo, $RemotePath)
                Write-Verbose "Uploaded $resolvedPath to $($s.ComputerName):$RemotePath"
            }
        }
        catch {
            Write-Error "SCP upload failed: $_"
        }
    }
}
