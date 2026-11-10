function New-SSHSession {
    <#
    .SYNOPSIS
        Opens a new SSH session to a remote host.
    .DESCRIPTION
        Connects to an SSH server, verifies its host key, authenticates and returns an
        SSHSessionInfo object. The session is kept in the module's session store until
        Remove-SSHSession is called or the module is removed. Other commands refer to
        it by its SessionId or take the object from the pipeline.

        The server's host key is checked against known_hosts before any credential is
        sent, following OpenSSH semantics:
        - known host, matching key: trusted
        - known host, different key: refused (possible man-in-the-middle)
        - key marked @revoked: refused
        - unknown host: depends on -StrictHostKeyChecking

        Authentication uses, in this order of preference: the key given with -KeyFile;
        the password in -Credential; or, when neither is given, the IdentityFile entries
        from the ssh config file followed by ~/.ssh/id_ed25519, id_ecdsa and id_rsa.
        Default keys that cannot be loaded, for example because they are protected by a
        passphrase, are skipped. -Credential and -KeyFile belong to different parameter
        sets and cannot be combined.

        HostName, User, Port and IdentityFile are read from ~/.ssh/config when present.
        Explicit parameters and user@host:port syntax take precedence.
    .PARAMETER ComputerName
        One or more hosts to connect to. Supports [user@]host[:port] syntax; IPv6
        literals need brackets when a port is given ([::1]:2222). The name is also
        looked up as a Host pattern in the ssh config file. Aliases: HostName, Host,
        Server, Target.
    .PARAMETER Port
        The SSH port. When omitted, the port in -ComputerName is used, then the Port
        from the ssh config file, then 22.
    .PARAMETER Credential
        A PSCredential for password authentication. The password is offered as
        "password" and as "keyboard-interactive"; in the latter only prompts that
        contain the word "password" are answered. The credential's user name is used
        unless -UserName or user@host is given.
    .PARAMETER UserName
        The user name for the connection. When omitted, the user in -ComputerName is
        used, then the user name of -Credential, then User from the ssh config file,
        then the current local user name.
    .PARAMETER KeyFile
        Path to a private key file for public key authentication. The file is loaded by
        SSH.NET. A relative path is resolved against the current PowerShell location
        and ~ is expanded. Aliases: Identity, IdentityFile, KeyPath.
    .PARAMETER KeyPassphrase
        Passphrase for the private key file given with -KeyFile, as a SecureString.
    .PARAMETER AcceptKey
        Accept and record the host key of a host that is not yet in known_hosts without
        prompting. This turns the default mode Ask into AcceptNew; it has no effect
        when -StrictHostKeyChecking is set to Yes, No or AcceptNew. A host whose key has
        changed is still refused.
    .PARAMETER StrictHostKeyChecking
        How unknown and changed host keys are handled:
        - Ask (default): prompt before trusting an unknown host and record the key if
          the answer is "yes"; refuse changed keys. If the session cannot prompt, the
          connection is refused.
        - Yes: refuse unknown hosts and changed keys. Nothing is written to known_hosts.
        - AcceptNew: record and trust unknown hosts; refuse changed keys.
        - No: record and trust unknown hosts. A changed key is tolerated, with a
          warning, only when no password would be sent; with -Credential it is refused.
        A revoked key is refused in every mode.
    .PARAMETER KnownHostsPath
        Use this known_hosts file instead of ~/.ssh/known_hosts and the system-wide
        files. It is the only file consulted, and new keys are recorded in it.
    .PARAMETER ConfigFile
        OpenSSH client config file to read. Defaults to ~/.ssh/config; 'none' disables
        it. Only Host, HostName, User, Port and IdentityFile are honoured.
    .PARAMETER ConnectionTimeout
        Connection timeout in seconds, from 1 to 300. Defaults to 30.
    .PARAMETER KeepAliveInterval
        Seconds between keep-alive messages, from 0 to 300; 0 disables them. Defaults
        to 15.
    .EXAMPLE
        New-SSHSession -ComputerName server01 -Credential (Get-Credential)

        Connects with password authentication. If server01 is not in known_hosts, you
        are shown the key fingerprint and asked whether to continue.
    .EXAMPLE
        New-SSHSession -ComputerName root@192.168.1.100:2222 -KeyFile ~/.ssh/id_ed25519

        Connects as root on port 2222 with a private key.
    .EXAMPLE
        $pass = Read-Host -AsSecureString -Prompt 'Key passphrase'
        $session = New-SSHSession server01 -UserName admin -KeyFile ./deploy_key -KeyPassphrase $pass -StrictHostKeyChecking Yes

        Uses a passphrase-protected key and refuses to connect unless the host key is
        already in known_hosts. Suitable for unattended scripts.
    .EXAMPLE
        $session = New-SSHSession server01 -UserName admin -AcceptKey

        Records the key of a host seen for the first time without prompting, and
        authenticates with the default keys in ~/.ssh.
    .OUTPUTS
        SSHSessionInfo
        One object per host that was connected, with SessionId, ComputerName, Port,
        UserName, AuthMethod, Connected, ConnectedAt, ServerVersion, ClientVersion,
        HostKeyType and HostKeyFingerprint.
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
