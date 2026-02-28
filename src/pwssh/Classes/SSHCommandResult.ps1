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

    # Success and OutputLines are provided via pwssh.Types.ps1xml as ScriptProperties

    [string] ToString() {
        return $this.Output
    }
}
