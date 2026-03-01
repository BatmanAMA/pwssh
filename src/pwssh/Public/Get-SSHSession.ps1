function Get-SSHSession {
    <#
    .SYNOPSIS
        Lists active SSH sessions.
    .DESCRIPTION
        Returns one or more SSHSessionInfo objects from the session store.
        Without parameters, returns all sessions.
    .PARAMETER SessionId
        One or more session IDs to retrieve.
    .PARAMETER ComputerName
        Filter sessions by computer name (supports wildcards).
    .PARAMETER Active
        Only return sessions that are currently connected.
    .EXAMPLE
        Get-SSHSession
    .EXAMPLE
        Get-SSHSession -SessionId 1, 2
    .EXAMPLE
        Get-SSHSession -ComputerName 'web*' -Active
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    [OutputType([SSHSessionInfo])]
    param(
        [Parameter(Position = 0, ParameterSetName = 'ById', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [int[]]$SessionId,

        [Parameter(ParameterSetName = 'ByName')]
        [Alias('HostName')]
        [string]$ComputerName,

        [Parameter()]
        [switch]$Active
    )

    begin {
        Initialize-SSHSessionStore
    }

    process {
        $sessions = switch ($PSCmdlet.ParameterSetName) {
            'ById' {
                foreach ($id in $SessionId) {
                    if ($script:SSHSessions.ContainsKey($id)) {
                        $script:SSHSessions[$id]
                    }
                    else {
                        Write-Error "Session $id not found."
                    }
                }
            }
            'ByName' {
                $script:SSHSessions.Values | Where-Object { $_.ComputerName -like $ComputerName }
            }
            default {
                $script:SSHSessions.Values
            }
        }

        if ($Active) {
            $sessions | Where-Object {
                $_.Connected -and (Test-SSHClientConnected -SessionId $_.SessionId)
            }
        }
        else {
            $sessions
        }
    }
}
