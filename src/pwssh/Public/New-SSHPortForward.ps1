function New-SSHPortForward {
    <#
    .SYNOPSIS
        Creates an SSH port forward (tunnel).
    .DESCRIPTION
        Sets up local, remote, or dynamic (SOCKS) port forwarding through an SSH session.
    .PARAMETER SessionId
        The session ID to use for the tunnel.
    .PARAMETER Session
        An SSHSessionInfo object.
    .PARAMETER Type
        The type of port forward: Local, Remote, or Dynamic.
    .PARAMETER BoundHost
        The local address to bind. Defaults to 'localhost'.
    .PARAMETER BoundPort
        The local port to bind.
    .PARAMETER RemoteHost
        The remote destination host (for Local and Remote forwarding).
    .PARAMETER RemotePort
        The remote destination port.
    .EXAMPLE
        New-SSHPortForward -SessionId 1 -Type Local -BoundPort 8080 -RemoteHost db.internal -RemotePort 5432
    .EXAMPLE
        New-SSHPortForward -SessionId 1 -Type Dynamic -BoundPort 1080
    .EXAMPLE
        New-SSHPortForward -SessionId 1 -Type Remote -BoundPort 9090 -RemoteHost localhost -RemotePort 80
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    [OutputType([SSHPortForward])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [int]$SessionId,

        [Parameter(Mandatory, ParameterSetName = 'BySession', ValueFromPipeline)]
        [SSHSessionInfo]$Session,

        [Parameter(Mandatory)]
        [ValidateSet('Local', 'Remote', 'Dynamic')]
        [string]$Type,

        [Parameter()]
        [string]$BoundHost = 'localhost',

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$BoundPort,

        [Parameter()]
        [string]$RemoteHost = 'localhost',

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$RemotePort
    )

    process {
        Initialize-SSHSessionStore

        $s = switch ($PSCmdlet.ParameterSetName) {
            'ById' {
                if ($script:SSHSessions.ContainsKey($SessionId)) { $script:SSHSessions[$SessionId] }
                else { Write-Error "Session $SessionId not found."; return }
            }
            'BySession' { $Session }
        }

        if (-not $s.Connected -or -not $s.InternalSession.IsConnected) {
            Write-Error "Session $($s.SessionId) is not connected."
            return
        }

        if ($Type -ne 'Dynamic' -and -not $RemotePort) {
            Write-Error "RemotePort is required for $Type port forwarding."
            return
        }

        try {
            $fwdPort = switch ($Type) {
                'Local' {
                    [Renci.SshNet.ForwardedPortLocal]::new($BoundHost, [uint32]$BoundPort, $RemoteHost, [uint32]$RemotePort)
                }
                'Remote' {
                    # SSH -R: BoundHost/BoundPort is where the remote side listens,
                    # RemoteHost/RemotePort is the local forwarding destination.
                    # Constructor signature: (boundHost, boundPort, host, port)
                    [Renci.SshNet.ForwardedPortRemote]::new($BoundHost, [uint32]$BoundPort, $RemoteHost, [uint32]$RemotePort)
                }
                'Dynamic' {
                    [Renci.SshNet.ForwardedPortDynamic]::new($BoundHost, [uint32]$BoundPort)
                }
            }

            $s.InternalSession.AddForwardedPort($fwdPort)
            $fwdPort.Start()

            $forward = [SSHPortForward]::new()
            $forward.ForwardId       = $script:NextForwardId++
            $forward.SessionId       = $s.SessionId
            $forward.Type            = $Type
            $forward.BoundHost       = $BoundHost
            $forward.BoundPort       = $BoundPort
            $forward.RemoteHost      = if ($Type -eq 'Dynamic') { '' } else { $RemoteHost }
            $forward.RemotePort      = if ($Type -eq 'Dynamic') { 0 } else { $RemotePort }
            $forward.IsStarted       = $fwdPort.IsStarted
            $forward.InternalForward = $fwdPort

            $script:SSHPortForwards[$forward.ForwardId] = $forward

            Write-Verbose "Port forward $($forward.ForwardId) started: $forward"
            $forward
        }
        catch {
            Write-Error "Failed to create port forward: $_"
        }
    }
}
