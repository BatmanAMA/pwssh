function Resolve-SSHHostName {
    <#
    .SYNOPSIS
        Parses a [user@]host[:port] connection string into components.
    .DESCRIPTION
        IPv6 literals must be bracketed to carry a port ([::1]:2222); an unbracketed
        address containing more than one colon is taken as a bare IPv6 address.
        Port is the port carried by the string, or -DefaultPort (22 unless given)
        when it carries none. HasPort tells the two cases apart.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [int]$DefaultPort = 22
    )

    $result = @{
        UserName     = $null
        ComputerName = $null
        Port         = $DefaultPort
        HasPort      = $false
    }

    $remaining = $Target

    # Extract user@ (the host part never contains '@', so split on the last one)
    $at = $remaining.LastIndexOf('@')
    if ($at -gt 0) {
        $result.UserName = $remaining.Substring(0, $at)
        $remaining = $remaining.Substring($at + 1)
    }

    $portText = $null
    if ($remaining -match '^\[([^\]]+)\]:(\d+)$') {
        $result.ComputerName = $Matches[1]
        $portText = $Matches[2]
    }
    elseif ($remaining -match '^\[([^\]]+)\]$') {
        $result.ComputerName = $Matches[1]
    }
    elseif ($remaining -match '^([^:]+):(\d+)$') {
        $result.ComputerName = $Matches[1]
        $portText = $Matches[2]
    }
    else {
        $result.ComputerName = $remaining
    }

    if ($portText) {
        $port = 0
        if (-not [int]::TryParse($portText, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
            throw "Invalid port '$portText' in '$Target'. The port must be between 1 and 65535."
        }
        $result.Port = $port
        $result.HasPort = $true
    }

    if ([string]::IsNullOrWhiteSpace($result.ComputerName) -or $result.ComputerName -match '\s') {
        throw "Invalid host name in '$Target'."
    }

    return [PSCustomObject]$result
}
