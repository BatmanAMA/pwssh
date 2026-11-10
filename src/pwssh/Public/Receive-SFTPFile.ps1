function Receive-SFTPFile {
    <#
    .SYNOPSIS
        Downloads a file from a remote host with SFTP.
    .DESCRIPTION
        Copies one remote file to the local machine using SFTP.

        If the local file already exists the command writes an error and transfers
        nothing, unless -Overwrite is given. The data is first written to a temporary
        file next to the destination (the destination name followed by a random
        identifier and the extension .part) and renamed when the download has
        completed. A failed download therefore leaves neither a partial file nor a
        damaged copy of the file being replaced. The parent directory of the
        destination is created if it does not exist.

        The transfer does not run over the session's own connection. The first SFTP
        command on a session opens a second connection with the session's connection
        settings; it is kept and reused by later SFTP commands and closed with the
        session. That connection is pinned to the host key the session accepted: if
        the server presents any other key the transfer is refused.
    .PARAMETER SessionId
        The ID of the session to use for the transfer.
    .PARAMETER Session
        The SSHSessionInfo object to use for the transfer. Accepts pipeline input.
    .PARAMETER RemotePath
        Path of the file on the remote host. Alias: Source.
    .PARAMETER LocalPath
        Path of the local file to write. A relative path is resolved against the
        current PowerShell location and ~ is expanded. Aliases: Destination, Path.
    .PARAMETER Overwrite
        Replace the local file if it exists.
    .EXAMPLE
        Receive-SFTPFile -SessionId 1 -RemotePath /var/log/app.log -LocalPath ./app.log
    .EXAMPLE
        Receive-SFTPFile -SessionId 1 -RemotePath /etc/myapp/config.yml -LocalPath ~/backup/config.yml -Overwrite

        Replaces an earlier local copy. The old copy is kept if the download fails.
    .OUTPUTS
        None
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
        $s = if ($PSCmdlet.ParameterSetName -eq 'ById') { Get-SSHTargetSession -SessionId $SessionId }
             else { Get-SSHTargetSession -Session $Session }
        if (-not $s) { return }

        $LocalPath = Resolve-SSHLocalPath -Path $LocalPath

        if ((Test-Path -LiteralPath $LocalPath) -and -not $Overwrite) {
            Write-Error "Local file '$LocalPath' already exists. Use -Overwrite to replace it."
            return
        }

        $parentDir = Split-Path $LocalPath -Parent
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        }

        try {
            $sftpClient = Get-SSHSubClient -Session $s -Type Sftp

            # Download to a temporary sibling so a failed transfer never leaves a
            # truncated file (or destroys the file being overwritten).
            $tempPath = "$LocalPath.$([guid]::NewGuid().ToString('N')).part"
            try {
                $stream = [System.IO.File]::Create($tempPath)
                try { $sftpClient.DownloadFile($RemotePath, $stream) }
                finally { $stream.Dispose() }

                if (Test-Path -LiteralPath $LocalPath) { Remove-Item -LiteralPath $LocalPath -Force }
                [System.IO.File]::Move($tempPath, $LocalPath)
                Write-Verbose "Downloaded $($s.ComputerName):$RemotePath to $LocalPath via SFTP"
            }
            finally {
                if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force }
            }
        }
        catch {
            Write-Error "SFTP download failed: $(Get-SSHErrorMessage $_)"
        }
    }
}
