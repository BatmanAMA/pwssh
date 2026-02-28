function Resolve-SSHHostName {
    <#
    .SYNOPSIS
        Parses a user@host:port connection string into components.
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
    }

    $remaining = $Target

    # Extract user@
    if ($remaining -match '^([^@]+)@(.+)$') {
        $result.UserName = $Matches[1]
        $remaining = $Matches[2]
    }

    # Extract host:port or [host]:port (IPv6)
    if ($remaining -match '^\[([^\]]+)\]:(\d+)$') {
        $result.ComputerName = $Matches[1]
        $result.Port = [int]$Matches[2]
    }
    elseif ($remaining -match '^\[([^\]]+)\]$') {
        $result.ComputerName = $Matches[1]
    }
    elseif ($remaining -match '^([^:]+):(\d+)$') {
        $result.ComputerName = $Matches[1]
        $result.Port = [int]$Matches[2]
    }
    else {
        $result.ComputerName = $remaining
    }

    return [PSCustomObject]$result
}
