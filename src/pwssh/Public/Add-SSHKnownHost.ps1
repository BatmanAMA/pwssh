function Add-SSHKnownHost {
    <#
    .SYNOPSIS
        Adds an entry to the SSH known_hosts file.
    .DESCRIPTION
        Appends a host key entry to the known_hosts file in OpenSSH format. An entry
        that is already present is not added twice. The input is validated first: the
        host name must be a single plain name or address (no whitespace, commas,
        wildcards or brackets), and the key data must be valid base64 that encodes a
        public key of the stated type. Supports -WhatIf and -Confirm.

        Adding a key makes New-SSHSession trust it. Only add keys whose fingerprint
        you have verified through a trusted channel.
    .PARAMETER HostName
        The host name or IP address.
    .PARAMETER Port
        The SSH port. Defaults to 22. Other ports are stored as [host]:port.
    .PARAMETER KeyType
        The key algorithm (for example ssh-ed25519 or ssh-rsa).
    .PARAMETER KeyData
        The base64-encoded public key data.
    .PARAMETER HostKey
        An SSHHostKey object from Get-SSHHostKey. Accepts pipeline input. Host name,
        port, key type and key data are taken from it.
    .PARAMETER HashHostName
        Store the host name hashed (like OpenSSH HashKnownHosts yes).
    .PARAMETER Path
        Path to the known_hosts file. Defaults to ~/.ssh/known_hosts.
    .EXAMPLE
        $key = Get-SSHHostKey server01
        $key.Fingerprint   # compare with the fingerprint from the server's administrator
        $key | Add-SSHKnownHost

        Retrieves the key, shows its fingerprint for comparison and then records it.
    .EXAMPLE
        Add-SSHKnownHost -HostName 10.0.0.1 -Port 2222 -KeyType ssh-ed25519 -KeyData 'AAAA...' -HashHostName

        Records a key received through a trusted channel, with the host name hashed.
    .OUTPUTS
        None
    #>
    [CmdletBinding(DefaultParameterSetName = 'Manual', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Manual')]
        [string]$HostName,

        [Parameter(ParameterSetName = 'Manual')]
        [ValidateRange(1, 65535)]
        [int]$Port = 22,

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$KeyType,

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$KeyData,

        [Parameter(Mandatory, ParameterSetName = 'FromHostKey', ValueFromPipeline)]
        [SSHHostKey]$HostKey,

        [Parameter()]
        [switch]$HashHostName,

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

        # Each field ends up verbatim in a whitespace-delimited line
        if ($HostName -notmatch '^[^\s,|#@!*?\[\]]+$') {
            Write-Error "Invalid host name '$HostName'."
            return
        }
        if ($KeyType -notmatch '^[A-Za-z0-9@._-]+$') {
            Write-Error "Invalid key type '$KeyType'."
            return
        }
        try {
            $blob = [System.Convert]::FromBase64String($KeyData)
        }
        catch {
            Write-Error 'KeyData is not valid base64.'
            return
        }
        if ([PwSSH.KnownHostsFile]::KeyTypeOfBlob($blob) -ne $KeyType) {
            Write-Error "KeyData is not a '$KeyType' public key."
            return
        }
        $KeyData = [System.Convert]::ToBase64String($blob)

        $hostSpec = [PwSSH.KnownHostsFile]::FormatHost($HostName, $Port)

        # Already recorded?
        $existing = [PwSSH.KnownHostsFile]::Parse($filePath) | Where-Object {
            -not $_.Marker -and $_.KeyBase64 -eq $KeyData -and $_.MatchesHost($hostSpec)
        }
        if ($existing) {
            Write-Verbose "$hostSpec ($KeyType) is already in $filePath"
            return
        }

        $hostEntry = if ($HashHostName) { [PwSSH.KnownHostsFile]::HashHost($hostSpec) } else { $hostSpec }
        $line = '{0} {1} {2}' -f $hostEntry, $KeyType, $KeyData

        if ($PSCmdlet.ShouldProcess($filePath, "Add known host entry for $hostSpec")) {
            [PwSSH.KnownHostsFile]::AppendLine($filePath, $line)
            Write-Verbose "Added $hostSpec to $filePath"
        }
    }
}
