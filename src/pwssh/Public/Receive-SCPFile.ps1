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
