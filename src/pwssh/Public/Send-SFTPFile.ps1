function Send-SFTPFile {
    <#
    .SYNOPSIS
        Uploads a file to a remote host with SFTP.
    .DESCRIPTION
        Copies one local file to the remote host using SFTP. The remote directory must
        exist. If the remote file already exists the upload fails unless -Overwrite is
        given. Directories cannot be uploaded with this command; use Send-SCPFile
        -Recurse for that.

        The transfer does not run over the session's own connection. The first SFTP
        command on a session opens a second connection with the session's connection
        settings; it is kept and reused by later SFTP commands and closed with the
        session. That connection is pinned to the host key the session accepted: if
        the server presents any other key the transfer is refused.
    .PARAMETER SessionId
        The ID of the session to use for the transfer.
    .PARAMETER Session
        The SSHSessionInfo object to use for the transfer. Accepts pipeline input.
    .PARAMETER LocalPath
        Path to the local file to upload. It must exist. A relative path is resolved
        against the current PowerShell location and ~ is expanded. Aliases: Source,
        Path.
    .PARAMETER RemotePath
        Destination file path on the remote host. Alias: Destination.
    .PARAMETER Overwrite
        Replace the remote file if it exists.
    .EXAMPLE
        Send-SFTPFile -SessionId 1 -LocalPath ./config.yml -RemotePath /etc/myapp/config.yml
    .EXAMPLE
        Get-SSHSession -ComputerName 'web*' -Active | ForEach-Object {
            $_ | Send-SFTPFile -LocalPath ~/site.conf -RemotePath /tmp/site.conf -Overwrite
        }

        Uploads the same file to several hosts, replacing an earlier copy.
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
        [Alias('Source', 'Path')]
        [string]$LocalPath,

        [Parameter(Mandatory, Position = 1)]
        [Alias('Destination')]
        [string]$RemotePath,

        [Parameter()]
        [switch]$Overwrite
    )

    process {
        $s = if ($PSCmdlet.ParameterSetName -eq 'ById') { Get-SSHTargetSession -SessionId $SessionId }
             else { Get-SSHTargetSession -Session $Session }
        if (-not $s) { return }

        try {
            $resolvedPath = Resolve-Path -Path $LocalPath -ErrorAction Stop

            $sftpClient = Get-SSHSubClient -Session $s -Type Sftp

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
            Write-Error "SFTP upload failed: $(Get-SSHErrorMessage $_)"
        }
    }
}
