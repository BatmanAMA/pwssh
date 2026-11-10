function Receive-SCPFile {
    <#
    .SYNOPSIS
        Downloads a file or directory from a remote host with SCP.
    .DESCRIPTION
        Copies a remote file, or with -Recurse a remote directory, to the local machine
        using the SCP protocol.

        The transfer does not run over the session's own connection. The first SCP
        command on a session opens a second connection with the session's connection
        settings; it is kept and reused by later SCP commands and closed with the
        session. That connection is pinned to the host key the session accepted: if
        the server presents any other key the transfer is refused.

        There is no overwrite check: an existing local file is written over. Use
        Receive-SFTPFile when an existing file must not be replaced by accident.
    .PARAMETER SessionId
        The ID of the session to use for the transfer.
    .PARAMETER Session
        The SSHSessionInfo object to use for the transfer. Accepts pipeline input.
    .PARAMETER RemotePath
        Path of the file or directory on the remote host. Alias: Source.
    .PARAMETER LocalPath
        Local destination. Without -Recurse this is the path of the file to write; its
        parent directory is created if needed. With -Recurse it is a directory, created
        if needed, that receives the download. A relative path is resolved against the
        current PowerShell location and ~ is expanded. Aliases: Destination, Path.
    .PARAMETER Recurse
        Download a directory and everything below it into the LocalPath directory.
        Required when RemotePath is a directory.
    .EXAMPLE
        Receive-SCPFile -SessionId 1 -RemotePath /var/log/syslog -LocalPath ./syslog.txt
    .EXAMPLE
        Receive-SCPFile -SessionId 1 -RemotePath /etc/nginx/ -LocalPath ./nginx-conf/ -Recurse

        Copies the contents of /etc/nginx into ./nginx-conf, creating it if needed.
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
        [switch]$Recurse
    )

    process {
        $s = if ($PSCmdlet.ParameterSetName -eq 'ById') { Get-SSHTargetSession -SessionId $SessionId }
             else { Get-SSHTargetSession -Session $Session }
        if (-not $s) { return }

        try {
            $LocalPath = Resolve-SSHLocalPath -Path $LocalPath
            $scpClient = Get-SSHSubClient -Session $s -Type Scp

            if ($Recurse) {
                $dirInfo = [System.IO.DirectoryInfo]::new($LocalPath)
                if (-not $dirInfo.Exists) { $dirInfo.Create() }
                $scpClient.Download($RemotePath, $dirInfo)
                Write-Verbose "Downloaded $($s.ComputerName):$RemotePath to $LocalPath"
            }
            else {
                $parentDir = Split-Path $LocalPath -Parent
                if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
                    New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
                }
                $fileInfo = [System.IO.FileInfo]::new($LocalPath)
                $scpClient.Download($RemotePath, $fileInfo)
                Write-Verbose "Downloaded $($s.ComputerName):$RemotePath to $LocalPath"
            }
        }
        catch {
            Write-Error "SCP download failed: $(Get-SSHErrorMessage $_)"
        }
    }
}
