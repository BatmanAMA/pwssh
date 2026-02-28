class SSHCommandResult {
    [int]$SessionId
    [string]$ComputerName
    [string]$Command
    [int]$ExitCode
    [string]$Output
    [string]$Error
    [timespan]$Duration
    [datetime]$StartTime
    [datetime]$EndTime

    SSHCommandResult() { }

    [bool] get_Success() {
        return $this.ExitCode -eq 0
    }

    [string[]] get_OutputLines() {
        if ([string]::IsNullOrEmpty($this.Output)) { return @() }
        return $this.Output -split "`n"
    }

    [string] ToString() {
        return $this.Output
    }
}
