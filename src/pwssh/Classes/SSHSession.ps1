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
    [object]$InternalSftpClient  # Cached Renci.SshNet.SftpClient
    [object]$InternalScpClient   # Cached Renci.SshNet.ScpClient
    [string]$VerifiedHostKeyFingerprint  # SHA256 fingerprint verified during initial connection

    SSHSessionInfo() {
        $this.Port = 22
        $this.ConnectedAt = [datetime]::UtcNow
    }

    [string] ToString() {
        $state = if ($this.Connected) { 'Open' } else { 'Closed' }
        return "[{0}] {1}@{2}:{3} ({4})" -f $this.SessionId, $this.UserName, $this.ComputerName, $this.Port, $state
    }

    [object] GetSftpClient() {
        if ($this.InternalSftpClient -and $this.InternalSftpClient.IsConnected) {
            return $this.InternalSftpClient
        }
        if ($this.InternalSftpClient) {
            try { $this.InternalSftpClient.Dispose() } catch { }
        }
        $this.InternalSftpClient = [Renci.SshNet.SftpClient]::new($this.InternalSession.ConnectionInfo)
        # Verify host key on the SFTP sub-connection matches the verified SSH session key
        $verifiedFp = $this.VerifiedHostKeyFingerprint
        if ($verifiedFp) {
            $this.InternalSftpClient.add_HostKeyReceived({
                param($sender, $e)
                $fp = ConvertTo-SSHFingerprint -KeyData $e.HostKey -Algorithm SHA256
                $e.CanTrust = ($fp -eq $verifiedFp)
            })
        }
        $this.InternalSftpClient.Connect()
        return $this.InternalSftpClient
    }

    [object] GetScpClient() {
        if ($this.InternalScpClient -and $this.InternalScpClient.IsConnected) {
            return $this.InternalScpClient
        }
        if ($this.InternalScpClient) {
            try { $this.InternalScpClient.Dispose() } catch { }
        }
        $this.InternalScpClient = [Renci.SshNet.ScpClient]::new($this.InternalSession.ConnectionInfo)
        # Verify host key on the SCP sub-connection matches the verified SSH session key
        $verifiedFp = $this.VerifiedHostKeyFingerprint
        if ($verifiedFp) {
            $this.InternalScpClient.add_HostKeyReceived({
                param($sender, $e)
                $fp = ConvertTo-SSHFingerprint -KeyData $e.HostKey -Algorithm SHA256
                $e.CanTrust = ($fp -eq $verifiedFp)
            })
        }
        $this.InternalScpClient.Connect()
        return $this.InternalScpClient
    }

    [void] Disconnect() {
        if ($this.InternalSftpClient) {
            try { $this.InternalSftpClient.Disconnect(); $this.InternalSftpClient.Dispose() } catch { }
            $this.InternalSftpClient = $null
        }
        if ($this.InternalScpClient) {
            try { $this.InternalScpClient.Disconnect(); $this.InternalScpClient.Dispose() } catch { }
            $this.InternalScpClient = $null
        }
        if ($this.InternalSession -and $this.Connected) {
            $this.InternalSession.Disconnect()
            $this.InternalSession.Dispose()
            $this.Connected = $false
        }
    }
}
