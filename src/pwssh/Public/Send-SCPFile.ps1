function Send-SCPFile {
    <#
    .SYNOPSIS
        Uploads a file or directory to a remote host with SCP.
    .DESCRIPTION
        Copies a local file, or with -Recurse a local directory, to the remote host
        using the SCP protocol.

        The transfer does not run over the session's own connection. The first SCP
        command on a session opens a second connection with the session's connection
        settings; it is kept and reused by later SCP commands and closed with the
        session. That connection is pinned to the host key the session accepted: if
        the server presents any other key the transfer is refused.

        SCP has no overwrite check, so an existing remote file is replaced. When a
        directory is uploaded, RemotePath must be an existing directory and the
        contents of the local directory are copied into it.
    .PARAMETER SessionId
        The ID of the session to use for the transfer.
    .PARAMETER Session
        The SSHSessionInfo object to use for the transfer. Accepts pipeline input.
    .PARAMETER LocalPath
        Path to the local file or directory to upload. It must exist. A relative path
        is resolved against the current PowerShell location and ~ is expanded.
        Aliases: Source, Path.
    .PARAMETER RemotePath
        Destination path on the remote host. Alias: Destination.
    .PARAMETER Recurse
        Upload a directory and everything below it. Required when LocalPath is a
        directory.
    .EXAMPLE
        Send-SCPFile -SessionId 1 -LocalPath ./app.tar.gz -RemotePath /tmp/app.tar.gz
    .EXAMPLE
        Send-SCPFile -SessionId 1 -LocalPath ./deploy/ -RemotePath /opt/app/ -Recurse

        Copies the contents of ./deploy into the existing remote directory /opt/app.
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
        [switch]$Recurse
    )

    process {
        $s = if ($PSCmdlet.ParameterSetName -eq 'ById') { Get-SSHTargetSession -SessionId $SessionId }
             else { Get-SSHTargetSession -Session $Session }
        if (-not $s) { return }

        try {
            $resolvedPath = Resolve-Path -Path $LocalPath -ErrorAction Stop

            $scpClient = Get-SSHSubClient -Session $s -Type Scp

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
            Write-Error "SCP upload failed: $(Get-SSHErrorMessage $_)"
        }
    }
}
