class SSHPortForward {
    [int]$ForwardId
    [int]$SessionId
    [string]$Type                # Local, Remote, Dynamic
    [string]$BoundHost
    [int]$BoundPort
    [string]$RemoteHost
    [int]$RemotePort
    [bool]$IsStarted
    [object]$InternalForward     # Renci.SshNet.ForwardedPort* (hidden from default display)

    SSHPortForward() { }

    [string] ToString() {
        switch ($this.Type) {
            'Local'   { return "L:{0}:{1} -> {2}:{3}" -f $this.BoundHost, $this.BoundPort, $this.RemoteHost, $this.RemotePort }
            'Remote'  { return "R:{0}:{1} -> {2}:{3}" -f $this.RemoteHost, $this.RemotePort, $this.BoundHost, $this.BoundPort }
            'Dynamic' { return "D:{0}:{1}" -f $this.BoundHost, $this.BoundPort }
            default   { return "$($this.Type):$($this.BoundPort)" }
        }
    }

    [void] Stop() {
        if ($this.InternalForward -and $this.IsStarted) {
            $this.InternalForward.Stop()
            $this.IsStarted = $false
        }
    }
}
