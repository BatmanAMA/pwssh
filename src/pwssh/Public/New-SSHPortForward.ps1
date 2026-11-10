function New-SSHPortForward {
    <#
    .SYNOPSIS
        Creates an SSH port forward (tunnel) on an existing session.
    .DESCRIPTION
        Starts local, remote or dynamic port forwarding through an SSH session and
        returns an SSHPortForward object. The forward stays active until it is removed
        with Remove-SSHPortForward or its session is closed.

        The meaning of the parameters depends on -Type:

        Local (like ssh -L): this computer listens on BoundHost:BoundPort. Connections
        are sent through the session and opened by the server to RemoteHost:RemotePort,
        so RemoteHost is resolved from the server's point of view.

        Remote (like ssh -R): the server listens on BoundHost:BoundPort. Connections
        are sent back through the session and opened by this computer to
        RemoteHost:RemotePort, so RemoteHost is resolved from this computer's point of
        view. Whether the server binds an address other than its loopback address is
        decided by the server's configuration.

        Dynamic (like ssh -D): this computer runs a SOCKS proxy on BoundHost:BoundPort.
        RemoteHost and RemotePort are not used.
    .PARAMETER SessionId
        The ID of the session to carry the forward.
    .PARAMETER Session
        The SSHSessionInfo object to carry the forward. Accepts pipeline input.
    .PARAMETER Type
        The kind of forward: Local, Remote or Dynamic.
    .PARAMETER BoundHost
        The address to listen on. For Local and Dynamic this is an address of this
        computer; for Remote it is an address of the server. Defaults to 'localhost'.
    .PARAMETER BoundPort
        The port to listen on: a port of this computer for Local and Dynamic, a port
        of the server for Remote.
    .PARAMETER RemoteHost
        The host connections are forwarded to. For Local it is reached from the
        server; for Remote it is reached from this computer. Ignored for Dynamic.
        Defaults to 'localhost'.
    .PARAMETER RemotePort
        The port on RemoteHost that connections are forwarded to. Required for Local
        and Remote; ignored for Dynamic.
    .EXAMPLE
        New-SSHPortForward -SessionId 1 -Type Local -BoundPort 8080 -RemoteHost db.internal -RemotePort 5432

        Connections to localhost:8080 on this computer reach db.internal:5432 as seen
        from the server.
    .EXAMPLE
        New-SSHPortForward -SessionId 1 -Type Dynamic -BoundPort 1080

        Runs a SOCKS proxy on localhost:1080 that connects through the server.
    .EXAMPLE
        New-SSHPortForward -SessionId 1 -Type Remote -BoundPort 9090 -RemoteHost localhost -RemotePort 80

        Connections to port 9090 on the server's loopback address reach port 80 on
        this computer.
    .OUTPUTS
        SSHPortForward
        Properties: ForwardId, SessionId, Type, BoundHost, BoundPort, RemoteHost,
        RemotePort and IsStarted. For a Dynamic forward RemoteHost is empty and
        RemotePort is 0.
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
        $s = if ($PSCmdlet.ParameterSetName -eq 'ById') { Get-SSHTargetSession -SessionId $SessionId }
             else { Get-SSHTargetSession -Session $Session }
        if (-not $s) { return }

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
            Write-Error "Failed to create port forward: $(Get-SSHErrorMessage $_)"
        }
    }
}
