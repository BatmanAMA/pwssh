function Get-SFTPChildItem {
    <#
    .SYNOPSIS
        Lists files and directories on a remote host with SFTP.
    .DESCRIPTION
        Returns the contents of a remote directory, similar to Get-ChildItem. The
        entries "." and ".." are left out.

        The listing does not run over the session's own connection. The first SFTP
        command on a session opens a second connection with the session's connection
        settings; it is kept and reused by later SFTP commands and closed with the
        session. That connection is pinned to the host key the session accepted: if
        the server presents any other key the listing is refused.
    .PARAMETER SessionId
        The ID of the session to use.
    .PARAMETER Session
        The SSHSessionInfo object to use. Accepts pipeline input.
    .PARAMETER Path
        The remote directory to list. Defaults to '.', the directory the SFTP server
        starts in, which is normally the user's home directory.
    .PARAMETER Recurse
        Also list the contents of subdirectories, at any depth.
    .EXAMPLE
        Get-SFTPChildItem -SessionId 1 -Path /var/log
    .EXAMPLE
        Get-SFTPChildItem -SessionId 1 -Path /etc -Recurse |
            Where-Object { -not $_.IsDirectory -and $_.Name -like '*.conf' } |
            Select-Object FullName, Length, LastWriteTime

        Finds configuration files below /etc.
    .OUTPUTS
        Renci.SshNet.Sftp.SftpFile
        The SSH.NET file object, with properties such as Name, FullName, Length,
        IsDirectory, IsSymbolicLink and LastWriteTime.
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
        $s = if ($PSCmdlet.ParameterSetName -eq 'ById') { Get-SSHTargetSession -SessionId $SessionId }
             else { Get-SSHTargetSession -Session $Session }
        if (-not $s) { return }

        try {
            $sftpClient = Get-SSHSubClient -Session $s -Type Sftp

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
            Write-Error "SFTP listing failed: $(Get-SSHErrorMessage $_)"
        }
    }
}
