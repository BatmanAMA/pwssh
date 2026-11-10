function Get-SSHSession {
    <#
    .SYNOPSIS
        Lists the SSH sessions opened with New-SSHSession.
    .DESCRIPTION
        Returns SSHSessionInfo objects from the module's session store. Without
        parameters, all sessions are returned, including ones whose connection has
        dropped. Sessions stay in the store until Remove-SSHSession removes them.
    .PARAMETER SessionId
        One or more session IDs to retrieve. An error is written for an ID that does
        not exist.
    .PARAMETER ComputerName
        Return only sessions whose ComputerName matches this value. Wildcards are
        supported. Alias: HostName.
    .PARAMETER Active
        Return only sessions that are still connected.
    .EXAMPLE
        Get-SSHSession

        Lists every session.
    .EXAMPLE
        Get-SSHSession -SessionId 1, 2
    .EXAMPLE
        Get-SSHSession -ComputerName 'web*' -Active

        Lists the connected sessions to hosts whose name starts with "web".
    .OUTPUTS
        SSHSessionInfo
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
                $_.Connected -and $_.InternalSession -and $_.InternalSession.IsConnected
            }
        }
        else {
            $sessions
        }
    }
}
