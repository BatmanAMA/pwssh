function New-SSHSession {
    <#
    .SYNOPSIS
        Opens a new SSH session to a remote host.
    .DESCRIPTION
        Creates an SSH connection using password, key-based, or default key authentication.
        Returns an SSHSessionInfo object representing the session.
    .PARAMETER ComputerName
        The hostname or IP address to connect to. Supports user@host:port syntax.
    .PARAMETER Port
        The SSH port. Defaults to 22.
    .PARAMETER Credential
        A PSCredential for password-based authentication. The username from the credential
        is used if -UserName is not specified.
    .PARAMETER UserName
        The username for the SSH connection. Overrides the credential username.
    .PARAMETER KeyFile
        Path to a private key file for public key authentication.
    .PARAMETER KeyPassphrase
        Passphrase for the private key file as a SecureString.
    .PARAMETER AcceptKey
        Automatically accept the host key without prompting.
    .PARAMETER ConnectionTimeout
        Connection timeout in seconds. Defaults to 30.
    .PARAMETER KeepAliveInterval
        Keep-alive interval in seconds. Defaults to 15. Set to 0 to disable.
    .EXAMPLE
        New-SSHSession -ComputerName server01 -Credential (Get-Credential)
    .EXAMPLE
        New-SSHSession -ComputerName root@192.168.1.100:2222 -KeyFile ~/.ssh/id_ed25519
    .EXAMPLE
        $session = New-SSHSession server01 -UserName admin -AcceptKey
    #>
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    [OutputType([SSHSessionInfo])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('HostName', 'Host', 'Server', 'Target')]
        [string[]]$ComputerName,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [Parameter(ParameterSetName = 'Credential')]
        [pscredential]$Credential,

        [Parameter()]
        [string]$UserName,

        [Parameter(ParameterSetName = 'KeyFile')]
        [Alias('Identity', 'IdentityFile', 'KeyPath')]
        [string]$KeyFile,

        [Parameter(ParameterSetName = 'KeyFile')]
        [securestring]$KeyPassphrase,

        [Parameter()]
        [switch]$AcceptKey,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$ConnectionTimeout = 30,

        [Parameter()]
        [ValidateRange(0, 300)]
        [int]$KeepAliveInterval = 15
    )

    begin {
        Initialize-SSHSessionStore
    }

    process {
        foreach ($target in $ComputerName) {
            $parsed = Resolve-SSHHostName -Target $target
            $hostName = $parsed.ComputerName
            $hostPort = if ($Port) { $Port } else { $parsed.Port }
            $user = if ($UserName) { $UserName }
                    elseif ($parsed.UserName) { $parsed.UserName }
                    elseif ($Credential) { $Credential.GetNetworkCredential().UserName }
                    else { if ($env:USER) { $env:USER } elseif ($env:USERNAME) { $env:USERNAME } else { 'root' } }

            Write-Verbose "Connecting to ${user}@${hostName}:${hostPort}..."

            try {
                $authMethods = Get-SSHAuthMethod -UserName $user -Credential $Credential -KeyFile $KeyFile -KeyPassphrase $KeyPassphrase
                if ($authMethods.Count -eq 0) {
                    throw "No authentication method available. Provide -Credential, -KeyFile, or place a key in ~/.ssh/"
                }

                $connInfo = [Renci.SshNet.ConnectionInfo]::new(
                    $hostName,
                    $hostPort,
                    $user,
                    [Renci.SshNet.AuthenticationMethod[]]$authMethods
                )
                $connInfo.Timeout = [timespan]::FromSeconds($ConnectionTimeout)

                $client = [Renci.SshNet.SshClient]::new($connInfo)

                if ($KeepAliveInterval -gt 0) {
                    $client.KeepAliveInterval = [timespan]::FromSeconds($KeepAliveInterval)
                }

                # Host key validation
                $client.add_HostKeyReceived({
                    param($sender, $e)
                    if (-not $AcceptKey) {
                        $fp = ConvertTo-SSHFingerprint -KeyData $e.HostKey -Algorithm SHA256
                        Write-Warning "Host key for ${hostName}: $($e.HostKeyName) $fp"
                    }
                    $e.CanTrust = $true
                })

                $client.Connect()

                $authMethod = if ($KeyFile) { 'PublicKey' }
                              elseif ($Credential) { 'Password' }
                              else { 'PublicKey' }

                $session = [SSHSessionInfo]::new()
                $session.SessionId = $script:NextSessionId++
                $session.ComputerName = $hostName
                $session.Port = $hostPort
                $session.UserName = $user
                $session.AuthMethod = $authMethod
                $session.Connected = $client.IsConnected
                $session.ServerVersion = $connInfo.ServerVersion
                $session.ClientVersion = $connInfo.ClientVersion
                $session.InternalSession = $client

                $script:SSHSessions[$session.SessionId] = $session

                Write-Verbose "Session $($session.SessionId) connected to ${user}@${hostName}:${hostPort}"
                $session
            }
            catch {
                Write-Error "Failed to connect to ${user}@${hostName}:${hostPort}: $_"
            }
        }
    }
}
