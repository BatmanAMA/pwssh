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
