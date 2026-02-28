function Remove-SSHSession {
    <#
    .SYNOPSIS
        Closes and removes one or more SSH sessions.
    .DESCRIPTION
        Disconnects the SSH client and removes the session from the session store.
    .PARAMETER SessionId
        One or more session IDs to remove.
    .PARAMETER Session
        One or more SSHSessionInfo objects to remove.
    .EXAMPLE
        Remove-SSHSession -SessionId 1
    .EXAMPLE
        Get-SSHSession | Remove-SSHSession
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'ById', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [int[]]$SessionId,

        [Parameter(Mandatory, ParameterSetName = 'BySession', ValueFromPipeline)]
        [SSHSessionInfo[]]$Session
    )

    begin {
        Initialize-SSHSessionStore
    }

    process {
        $targets = switch ($PSCmdlet.ParameterSetName) {
            'ById'      { $SessionId }
            'BySession' { $Session | ForEach-Object { $_.SessionId } }
        }

        foreach ($id in $targets) {
            if (-not $script:SSHSessions.ContainsKey($id)) {
                Write-Error "Session $id not found."
                continue
            }

            $s = $script:SSHSessions[$id]
            if ($PSCmdlet.ShouldProcess("$($s.UserName)@$($s.ComputerName):$($s.Port)", 'Disconnect')) {
                # Stop any port forwards attached to this session
                $forwards = $script:SSHPortForwards.Values | Where-Object { $_.SessionId -eq $id }
                foreach ($fwd in $forwards) {
                    $fwd.Stop()
                    $script:SSHPortForwards.Remove($fwd.ForwardId) | Out-Null
                }

                $s.Disconnect()
                $script:SSHSessions.Remove($id) | Out-Null
                Write-Verbose "Session $id disconnected."
            }
        }
    }
}
