function New-SSHSession {
    <#
    .SYNOPSIS
        Opens a new SSH session to a remote host.
    .DESCRIPTION
        Creates an SSH connection using key or password authentication and returns an
        SSHSessionInfo object.

        The server's host key is checked against known_hosts before any credential is
        sent, following OpenSSH semantics:
        - known host, matching key: trusted
        - known host, different key: refused (possible man-in-the-middle)
        - key marked @revoked: refused
        - unknown host: depends on -StrictHostKeyChecking

        HostName, User, Port and IdentityFile are read from ~/.ssh/config when present.
        Explicit parameters and user@host:port syntax take precedence.
    .PARAMETER ComputerName
        The host to connect to. Supports [user@]host[:port] syntax; IPv6 literals need
        brackets when a port is given ([::1]:2222).
    .PARAMETER Port
        The SSH port. Defaults to 22.
    .PARAMETER Credential
        A PSCredential for password authentication (also offered as
        keyboard-interactive). Its user name is used unless -UserName or user@host is given.
    .PARAMETER UserName
        The user name for the connection.
    .PARAMETER KeyFile
        Path to a private key file for public key authentication.
    .PARAMETER KeyPassphrase
        Passphrase for the private key file, as a SecureString.
    .PARAMETER AcceptKey
        Accept and record the host key of a host that is not yet in known_hosts without
        prompting (StrictHostKeyChecking AcceptNew). A host whose key has CHANGED is
        still refused.
    .PARAMETER StrictHostKeyChecking
        How unknown and changed host keys are handled:
        - Ask (default): prompt before trusting an unknown host; refuse changed keys
        - Yes: refuse unknown hosts and changed keys
        - AcceptNew: record and trust unknown hosts; refuse changed keys
        - No: record and trust unknown hosts. A changed key is tolerated only for
          key-based authentication; it is refused when a password would be sent.
    .PARAMETER KnownHostsPath
        Use this known_hosts file instead of ~/.ssh/known_hosts and the system-wide files.
    .PARAMETER ConfigFile
        OpenSSH client config file to read. Defaults to ~/.ssh/config; 'none' disables it.
    .PARAMETER ConnectionTimeout
        Connection timeout in seconds. Defaults to 30.
    .PARAMETER KeepAliveInterval
        Seconds between keep-alive messages; 0 disables them. Defaults to 15.
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
        [ValidateSet('Ask', 'Yes', 'No', 'AcceptNew')]
        [string]$StrictHostKeyChecking = 'Ask',

        [Parameter()]
        [string]$KnownHostsPath,

        [Parameter()]
        [string]$ConfigFile,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$ConnectionTimeout = 30,

        [Parameter()]
        [ValidateRange(0, 300)]
        [int]$KeepAliveInterval = 15
    )

    begin {
        Initialize-SSHSessionStore

        # -AcceptKey only relaxes the default; an explicit mode is honoured as given.
        $strictMode = if ($AcceptKey -and $StrictHostKeyChecking -eq 'Ask') { 'AcceptNew' } else { $StrictHostKeyChecking }
        $verifierMode = switch ($strictMode) {
            'Yes'       { [PwSSH.HostKeyMode]::Strict }
            'Ask'       { [PwSSH.HostKeyMode]::Ask }
            'AcceptNew' { [PwSSH.HostKeyMode]::AcceptNew }
            'No'        { [PwSSH.HostKeyMode]::Off }
        }
    }

    process {
        foreach ($target in $ComputerName) {
            $client = $null
            $hostName = $target
            $hostPort = if ($Port) { $Port } else { 22 }
            $user = $UserName

            try {
                if (-not ('Renci.SshNet.SshClient' -as [type])) {
                    throw 'SSH.NET is not loaded. Run build.ps1 to download the module dependencies.'
                }

                $parsed = Resolve-SSHHostName -Target $target

                $config = @{ HostName = $null; User = $null; Port = $null; IdentityFile = @() }
                if ($ConfigFile -ne 'none') {
                    $config = Get-SSHConfigHost -HostName $parsed.ComputerName -Path $ConfigFile
                }

                $hostName = if ($config.HostName) { $config.HostName } else { $parsed.ComputerName }
                $hostPort = if ($Port) { $Port }
                            elseif ($parsed.HasPort) { $parsed.Port }
                            elseif ($config.Port) { $config.Port }
                            else { 22 }
                $user = if ($UserName) { $UserName }
                        elseif ($parsed.UserName) { $parsed.UserName }
                        elseif ($Credential) { $Credential.GetNetworkCredential().UserName }
                        elseif ($config.User) { $config.User }
                        else { [System.Environment]::UserName }

                Write-Verbose "Connecting to ${user}@${hostName}:${hostPort}..."

                $auth = Get-SSHAuthMethod -UserName $user -Credential $Credential -KeyFile $KeyFile `
                    -KeyPassphrase $KeyPassphrase -IdentityFile $config.IdentityFile
                if (-not $auth -or @($auth.Methods).Count -eq 0) {
                    throw ('No authentication method available. Provide -Credential or -KeyFile, or place an ' +
                           'unencrypted key in ~/.ssh/ (passphrase-protected keys need -KeyFile with -KeyPassphrase).')
                }

                $userKnownHosts = Get-SSHKnownHostsPath -Path $KnownHostsPath
                $knownHostsFiles = @(Get-SSHKnownHostsPath -Path $KnownHostsPath -All)

                $prompted = $false
                while ($true) {
                    $connInfo = [Renci.SshNet.ConnectionInfo]::new(
                        $hostName,
                        $hostPort,
                        $user,
                        [Renci.SshNet.AuthenticationMethod[]]$auth.Methods
                    )
                    $connInfo.Timeout = [timespan]::FromSeconds($ConnectionTimeout)

                    $client = [Renci.SshNet.SshClient]::new($connInfo)
                    if ($KeepAliveInterval -gt 0) {
                        $client.KeepAliveInterval = [timespan]::FromSeconds($KeepAliveInterval)
                    }

                    # Host key verification runs in compiled code: SSH.NET raises the event
                    # on a thread that cannot run PowerShell.
                    $verifier = [PwSSH.HostKeyVerifier]::new()
                    $verifier.Mode = $verifierMode
                    $verifier.Host = $hostName
                    $verifier.Port = $hostPort
                    $verifier.KnownHostsPaths = [string[]]$knownHostsFiles
                    $verifier.UserKnownHostsPath = $userKnownHosts
                    $verifier.AllowChangedKey = -not $auth.SendsPassword
                    $verifier.Attach($client)

                    try {
                        $client.Connect()
                        break
                    }
                    catch {
                        try { $client.Dispose() } catch { }
                        $client = $null

                        $isUnknownHost = $verifier.Invoked -and
                            $verifier.Status -eq [PwSSH.HostKeyStatus]::New -and
                            $verifier.Mode -eq [PwSSH.HostKeyMode]::Ask
                        if ($isUnknownHost -and -not $prompted) {
                            # Ask on the pipeline thread, record the key, then reconnect. The
                            # second attempt only succeeds if the server presents this same key.
                            $prompted = $true
                            $where = [PwSSH.KnownHostsFile]::FormatHost($hostName, $hostPort)
                            $promptMsg = ("The authenticity of host '$where' can't be established.`n" +
                                          "$($verifier.KeyType) key fingerprint is $($verifier.Fingerprint).`n" +
                                          'Are you sure you want to continue connecting (yes/no)')
                            try { $answer = Read-Host -Prompt $promptMsg }
                            catch {
                                throw "Host key verification failed: '$where' is not a known host and this session cannot prompt. Use -AcceptKey or add the key with Add-SSHKnownHost."
                            }
                            if ("$answer".Trim() -ne 'yes') {
                                throw "Host key verification failed: the host key for '$where' was not accepted."
                            }
                            $line = '{0} {1} {2}' -f $where, $verifier.KeyType, [System.Convert]::ToBase64String($verifier.KeyBlob)
                            [PwSSH.KnownHostsFile]::AppendLine($userKnownHosts, $line)
                            Write-Warning "Permanently added '$where' ($($verifier.KeyType)) to the list of known hosts."
                            continue
                        }

                        if ($verifier.Error) { throw $verifier.Error }
                        throw
                    }
                }

                foreach ($w in $verifier.Warnings) { Write-Warning $w }

                # Defence in depth: never hand out a session whose host key was not approved.
                if (-not ($verifier.Invoked -and $verifier.Trusted)) {
                    throw "Host key verification did not complete for ${hostName}:${hostPort}."
                }

                $session = [SSHSessionInfo]::new()
                $session.SessionId          = $script:NextSessionId++
                $session.ComputerName       = $hostName
                $session.Port               = $hostPort
                $session.UserName           = $user
                $session.AuthMethod         = $auth.Description
                $session.Connected          = $client.IsConnected
                $session.ServerVersion      = $connInfo.ServerVersion
                $session.ClientVersion      = $connInfo.ClientVersion
                $session.HostKeyType        = $verifier.KeyType
                $session.HostKeyFingerprint = $verifier.Fingerprint
                $session.HostKey            = $verifier.KeyBlob
                $session.InternalSession    = $client

                $script:SSHSessions[$session.SessionId] = $session
                $client = $null

                Write-Verbose "Session $($session.SessionId) connected to ${user}@${hostName}:${hostPort}"
                $session
            }
            catch {
                if ($client) { try { $client.Dispose() } catch { } }
                Write-Error "Failed to connect to ${user}@${hostName}:${hostPort}: $(Get-SSHErrorMessage $_)"
            }
        }
    }
}
