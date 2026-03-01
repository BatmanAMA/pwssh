class SSHSessionInfo {
    [int]$SessionId
    [string]$ComputerName
    [int]$Port
    [string]$UserName
    [string]$AuthMethod          # Password, PublicKey, KeyboardInteractive
    [bool]$Connected
    [datetime]$ConnectedAt
    [string]$ServerVersion
    [string]$ClientVersion
    # NOTE: Raw SSH clients are stored in $script:SSHClients (module-scoped)
    # and are NOT exposed on this object. This prevents callers from bypassing
    # module security controls (host key verification, logging, session management).

    SSHSessionInfo() {
        $this.Port = 22
        $this.ConnectedAt = [datetime]::UtcNow
    }

    [string] ToString() {
        $state = if ($this.Connected) { 'Open' } else { 'Closed' }
        return "[{0}] {1}@{2}:{3} ({4})" -f $this.SessionId, $this.UserName, $this.ComputerName, $this.Port, $state
    }
}
