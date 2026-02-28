function New-SSHSession {
    <#
    .SYNOPSIS
        Opens a new SSH session to a remote host.
    .DESCRIPTION
        Creates an SSH connection using password, key-based, or default key authentication.
        Returns an SSHSessionInfo object representing the session.

        Host key verification uses TOFU (Trust On First Use) by default:
        - Known host with matching key: trusted automatically
        - Known host with CHANGED key: connection refused (MITM protection)
        - Unknown host: prompts to accept (or use -AcceptKey to auto-accept)
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
        Automatically accept and trust the host key without prompting.
        Equivalent to OpenSSH StrictHostKeyChecking=no.
    .PARAMETER StrictHostKeyChecking
        Host key verification mode:
        - Ask (default): prompt for unknown hosts, reject changed keys
        - Yes: reject both unknown and changed keys
        - No: accept all keys (same as -AcceptKey)
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
        [ValidateSet('Ask', 'Yes', 'No')]
        [string]$StrictHostKeyChecking = 'Ask',

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
                    else {
                        if ($env:USER) { $env:USER }
                        elseif ($env:USERNAME) { $env:USERNAME }
                        else { throw "Cannot determine SSH username. No -UserName, -Credential, or USER/USERNAME environment variable found. Provide an explicit -UserName parameter." }
                    }

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

                # Snapshot loop variables for the closure (avoids capture-by-reference bug
                # where the foreach variable advances before the event fires)
                $currentHost = $hostName
                $currentPort = $hostPort
                $currentAcceptKey = [bool]$AcceptKey

                # -AcceptKey overrides StrictHostKeyChecking to 'No'
                $currentStrictMode = if ($currentAcceptKey) { 'No' } else { $StrictHostKeyChecking }

                # Security warning: host key verification disabled
                if ($currentStrictMode -eq 'No') {
                    Write-Warning ("Host key verification is disabled for ${hostName}:${hostPort}. " +
                        "This connection is vulnerable to man-in-the-middle attacks. " +
                        "Do not use -AcceptKey or StrictHostKeyChecking=No in production.")
                }

                # Shared hashtable for cross-scope communication with the event handler
                $hostKeyResult = @{ CanTrust = $false; Error = $null; Fingerprint = $null }

                # Host key validation — proper TOFU (Trust On First Use)
                $client.add_HostKeyReceived({
                    param($sender, $e)

                    $fp = ConvertTo-SSHFingerprint -KeyData $e.HostKey -Algorithm SHA256

                    if ($currentStrictMode -eq 'No') {
                        $e.CanTrust = $true
                        $hostKeyResult.CanTrust = $true
                        $hostKeyResult.Fingerprint = $fp
                        return
                    }

                    # Look up this host in known_hosts
                    $known = Get-SSHKnownHost -HostName $currentHost |
                        Where-Object { $_.Port -eq $currentPort -and $_.KeyType -eq $e.HostKeyName }

                    if ($known) {
                        # Host is known — verify fingerprint matches
                        $knownFp = $known | Select-Object -First 1 -ExpandProperty Fingerprint
                        if ($knownFp -eq $fp) {
                            $e.CanTrust = $true
                            $hostKeyResult.CanTrust = $true
                            $hostKeyResult.Fingerprint = $fp
                        }
                        else {
                            # KEY MISMATCH — possible MITM attack
                            $e.CanTrust = $false
                            $hostKeyResult.CanTrust = $false
                            $hostKeyResult.Error = (
                                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`n" +
                                "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!        @`n" +
                                "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`n" +
                                "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!`n" +
                                "The $($e.HostKeyName) host key for ${currentHost}:${currentPort} has changed.`n" +
                                "Expected: $knownFp`n" +
                                "Received: $fp`n" +
                                "Host key verification failed."
                            )
                        }
                    }
                    else {
                        # Unknown host
                        if ($currentStrictMode -eq 'Yes') {
                            $e.CanTrust = $false
                            $hostKeyResult.CanTrust = $false
                            $hostKeyResult.Error = "Host key for ${currentHost}:${currentPort} not found in known_hosts. StrictHostKeyChecking is 'Yes'."
                            return
                        }

                        # Ask mode — prompt the user
                        try {
                            $promptMsg = ("The authenticity of host '${currentHost}:${currentPort}' can't be established.`n" +
                                         "$($e.HostKeyName) key fingerprint is ${fp}.`n" +
                                         "Are you sure you want to continue connecting? (yes/no)")
                            $answer = Read-Host -Prompt $promptMsg
                        }
                        catch {
                            $e.CanTrust = $false
                            $hostKeyResult.CanTrust = $false
                            $hostKeyResult.Error = "Host key verification failed: non-interactive session cannot prompt for unknown host."
                            return
                        }

                        if ($answer -eq 'yes') {
                            $e.CanTrust = $true
                            $hostKeyResult.CanTrust = $true
                            $hostKeyResult.Fingerprint = $fp
                            # Persist to known_hosts
                            $b64Key = [System.Convert]::ToBase64String($e.HostKey)
                            Add-SSHKnownHost -HostName $currentHost -Port $currentPort -KeyType $e.HostKeyName -KeyData $b64Key
                            Write-Warning "Permanently added '${currentHost}:${currentPort}' ($($e.HostKeyName)) to the list of known hosts."
                        }
                        else {
                            $e.CanTrust = $false
                            $hostKeyResult.CanTrust = $false
                            $hostKeyResult.Error = "Host key verification failed: user rejected the key."
                        }
                    }
                })

                $client.Connect()

                # Verify host key verification actually passed
                if (-not $hostKeyResult.CanTrust) {
                    $client.Dispose()
                    if ($hostKeyResult.Error) {
                        throw $hostKeyResult.Error
                    }
                    throw "Host key verification failed for ${hostName}:${hostPort}."
                }

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
                $session.VerifiedHostKeyFingerprint = $hostKeyResult.Fingerprint

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
