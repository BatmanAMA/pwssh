function Add-SSHKnownHost {
    <#
    .SYNOPSIS
        Adds an entry to the SSH known_hosts file.
    .DESCRIPTION
        Appends a host key entry to the known_hosts file in OpenSSH format.
    .PARAMETER HostName
        The hostname or IP address.
    .PARAMETER Port
        The SSH port. Defaults to 22.
    .PARAMETER KeyType
        The key algorithm (e.g. ssh-ed25519, ssh-rsa).
    .PARAMETER KeyData
        The base64-encoded public key data.
    .PARAMETER HostKey
        An SSHHostKey object (from Get-SSHHostKey).
    .PARAMETER Path
        Path to the known_hosts file. Defaults to ~/.ssh/known_hosts.
    .EXAMPLE
        Get-SSHHostKey github.com | Add-SSHKnownHost
    .EXAMPLE
        Add-SSHKnownHost -HostName 10.0.0.1 -KeyType ssh-ed25519 -KeyData 'AAAA...'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Manual', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Manual')]
        [string]$HostName,

        [Parameter(ParameterSetName = 'Manual')]
        [int]$Port = 22,

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$KeyType,

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$KeyData,

        [Parameter(Mandatory, ParameterSetName = 'FromHostKey', ValueFromPipeline)]
        [SSHHostKey]$HostKey,

        [Parameter()]
        [string]$Path
    )

    process {
        $filePath = Get-SSHKnownHostsPath -Path $Path

        if ($PSCmdlet.ParameterSetName -eq 'FromHostKey') {
            $HostName = $HostKey.ComputerName
            $Port     = $HostKey.Port
            $KeyType  = $HostKey.KeyType
            $KeyData  = [System.Convert]::ToBase64String($HostKey.RawKey)
        }

        $hostEntry = if ($Port -eq 22) { $HostName } else { "[{0}]:{1}" -f $HostName, $Port }
        $line = "{0} {1} {2}" -f $hostEntry, $KeyType, $KeyData

        if ($PSCmdlet.ShouldProcess($filePath, "Add known host entry for $hostEntry")) {
            # Use exclusive file lock to prevent race conditions with concurrent sessions
            $fs = $null
            try {
                $fs = [System.IO.FileStream]::new(
                    $filePath,
                    [System.IO.FileMode]::Append,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None
                )
                $bytes = [System.Text.Encoding]::UTF8.GetBytes("$line`n")
                $fs.Write($bytes, 0, $bytes.Length)
            }
            finally {
                if ($fs) { $fs.Dispose() }
            }
            Write-Verbose "Added $hostEntry to $filePath"
        }
    }
}
