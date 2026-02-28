function Invoke-SSHCommand {
    <#
    .SYNOPSIS
        Executes a command on a remote host via SSH.
    .DESCRIPTION
        Runs one or more commands on the specified SSH session(s) and returns
        SSHCommandResult objects containing stdout, stderr, and exit code.
    .PARAMETER SessionId
        The session ID(s) to execute the command on.
    .PARAMETER Session
        SSHSessionInfo object(s) to execute the command on.
    .PARAMETER Command
        The command string to execute on the remote host.
    .PARAMETER ScriptBlock
        A script block whose string representation is executed remotely.
    .PARAMETER Timeout
        Command timeout in seconds. Defaults to 0 (no timeout).
    .EXAMPLE
        Invoke-SSHCommand -SessionId 1 -Command 'uname -a'
    .EXAMPLE
        $result = Invoke-SSHCommand -SessionId 1,2 -Command 'df -h'
        $result | Where-Object { $_.ExitCode -ne 0 }
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
        [Alias('ScriptBlock')]
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

            Write-Verbose "Executing on session $($s.SessionId): $Command"
            $startTime = [datetime]::UtcNow

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
                $result.ExitCode     = $sshCmd.ExitStatus
                $result.Output       = $sshCmd.Result
                $result.Error        = $sshCmd.Error
                $result.StartTime    = $startTime
                $result.EndTime      = $endTime
                $result.Duration     = $endTime - $startTime

                $result
            }
            catch {
                Write-Error "Command execution failed on session $($s.SessionId): $_"
            }
            finally {
                if ($sshCmd) { $sshCmd.Dispose() }
            }
        }
    }
}
