function Invoke-SSHCommand {
    <#
    .SYNOPSIS
        Runs a command on a remote host over an SSH session.
    .DESCRIPTION
        Runs one command string on each of the given sessions, one session after the
        other, and returns an SSHCommandResult per session with the standard output,
        standard error and exit code.

        A non-zero exit code is not an error: check ExitCode or Success on the result.
        ExitCode is -1 when the server reported no exit status, for example because the
        command was killed by a signal; ExitSignal then holds the signal name if the
        server sent one. Success is true only when ExitCode is 0.

        The command text is not written to the verbose stream, because it may contain
        secrets. It is stored in the Command property of the result.
    .PARAMETER SessionId
        The ID of one or more sessions to run the command on.
    .PARAMETER Session
        One or more SSHSessionInfo objects to run the command on. Accepts pipeline
        input.
    .PARAMETER Command
        The command line to run on the remote host. The server passes it to the remote
        user's shell.
    .PARAMETER Timeout
        Command timeout in seconds, from 0 to 86400. Defaults to 0, which means no
        timeout. When the timeout is reached an error is written and no result object
        is returned for that session.
    .EXAMPLE
        Invoke-SSHCommand -SessionId 1 -Command 'uname -a'
    .EXAMPLE
        $result = Invoke-SSHCommand -SessionId 1,2 -Command 'df -h'
        $result | Where-Object { -not $_.Success } | Select-Object ComputerName, ExitCode, Error

        Runs the command on two sessions and shows the ones that failed.
    .EXAMPLE
        Get-SSHSession -Active | Invoke-SSHCommand -Command 'systemctl is-active nginx' -Timeout 30

        Runs the command on every connected session with a 30 second timeout.
    .OUTPUTS
        SSHCommandResult
        Properties: SessionId, ComputerName, Command, ExitCode, ExitSignal, Output,
        Error, StartTime, EndTime, Duration, Success and OutputLines.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    [OutputType([SSHCommandResult])]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'ById')]
        [int[]]$SessionId,

        [Parameter(Mandatory, ParameterSetName = 'BySession', ValueFromPipeline)]
        [SSHSessionInfo[]]$Session,

        [Parameter(Mandatory, Position = 1, ParameterSetName = 'ById')]
        [Parameter(Mandatory, Position = 1, ParameterSetName = 'BySession')]
        [string]$Command,

        [Parameter()]
        [ValidateRange(0, 86400)]
        [int]$Timeout = 0
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
            'BySession' { $Session }
        }

        foreach ($s in $sessions) {
            if (-not $s.Connected -or -not $s.InternalSession.IsConnected) {
                Write-Error "Session $($s.SessionId) is not connected."
                continue
            }

            # The command text is deliberately not logged: it may contain secrets.
            Write-Verbose "Executing command on session $($s.SessionId) ($($s.ComputerName))"
            $startTime = [datetime]::UtcNow

            $sshCmd = $null
            try {
                $sshCmd = $s.InternalSession.CreateCommand($Command)
                if ($Timeout -gt 0) {
                    $sshCmd.CommandTimeout = [timespan]::FromSeconds($Timeout)
                }

                $sshCmd.Execute()
                $endTime = [datetime]::UtcNow

                $result = [SSHCommandResult]::new()
                $result.SessionId    = $s.SessionId
                $result.ComputerName = $s.ComputerName
                $result.Command      = $Command
                # ExitStatus is null when the command was killed by a signal or the channel
                # closed without reporting a status; that must not look like success.
                $exitStatus = $sshCmd.ExitStatus
                $result.ExitCode     = if ($null -eq $exitStatus) { -1 } else { $exitStatus }
                if ($sshCmd.PSObject.Properties['ExitSignal']) { $result.ExitSignal = $sshCmd.ExitSignal }
                $result.Output       = $sshCmd.Result
                $result.Error        = $sshCmd.Error
                $result.StartTime    = $startTime
                $result.EndTime      = $endTime
                $result.Duration     = $endTime - $startTime

                $result
            }
            catch {
                Write-Error "Command execution failed on session $($s.SessionId): $(Get-SSHErrorMessage $_)"
            }
            finally {
                if ($sshCmd) { $sshCmd.Dispose() }
            }
        }
    }
}
