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
    [object]$InternalSession     # Renci.SshNet.SshClient (hidden from default display)

    SSHSessionInfo() {
        $this.Port = 22
        $this.ConnectedAt = [datetime]::UtcNow
    }

    [string] ToString() {
        $state = if ($this.Connected) { 'Open' } else { 'Closed' }
        return "[{0}] {1}@{2}:{3} ({4})" -f $this.SessionId, $this.UserName, $this.ComputerName, $this.Port, $state
    }

    [void] Disconnect() {
        if ($this.InternalSession -and $this.Connected) {
            $this.InternalSession.Disconnect()
            $this.InternalSession.Dispose()
            $this.Connected = $false
        }
    }
}
