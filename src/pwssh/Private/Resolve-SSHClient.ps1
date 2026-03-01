function Resolve-SSHClient {
    <#
    .SYNOPSIS
        Resolves the internal SSH client objects for a session from the module-scoped store.
    .DESCRIPTION
        Returns the internal client hashtable for a session ID from $script:SSHClients.
        This is a private function — callers never see the raw SSH client objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$SessionId
    )

    if ($script:SSHClients -and $script:SSHClients.ContainsKey($SessionId)) {
        return $script:SSHClients[$SessionId]
    }
    return $null
}

function Test-SSHClientConnected {
    <#
    .SYNOPSIS
        Tests whether an SSH session's underlying connection is alive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$SessionId
    )

    $clientInfo = Resolve-SSHClient -SessionId $SessionId
    if ($clientInfo -and $clientInfo.Client) {
        return $clientInfo.Client.IsConnected
    }
    return $false
}

function Get-SSHSftpClientInternal {
    <#
    .SYNOPSIS
        Gets or creates an SFTP client for a session, with host key verification.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$SessionId
    )

    $clientInfo = Resolve-SSHClient -SessionId $SessionId
    if (-not $clientInfo) { throw "No internal client found for session $SessionId" }

    if ($clientInfo.SftpClient -and $clientInfo.SftpClient.IsConnected) {
        return $clientInfo.SftpClient
    }
    if ($clientInfo.SftpClient) {
        try { $clientInfo.SftpClient.Dispose() } catch { }
    }

    $sftpClient = [Renci.SshNet.SftpClient]::new($clientInfo.Client.ConnectionInfo)
    # Verify host key on the SFTP sub-connection matches the verified SSH session key
    $verifiedFp = $clientInfo.Fingerprint
    if ($verifiedFp) {
        $sftpClient.add_HostKeyReceived({
            param($sender, $e)
            $fp = ConvertTo-SSHFingerprint -KeyData $e.HostKey -Algorithm SHA256
            $e.CanTrust = ($fp -eq $verifiedFp)
        })
    }
    $sftpClient.Connect()
    $clientInfo.SftpClient = $sftpClient
    return $sftpClient
}

function Get-SSHScpClientInternal {
    <#
    .SYNOPSIS
        Gets or creates an SCP client for a session, with host key verification.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$SessionId
    )

    $clientInfo = Resolve-SSHClient -SessionId $SessionId
    if (-not $clientInfo) { throw "No internal client found for session $SessionId" }

    if ($clientInfo.ScpClient -and $clientInfo.ScpClient.IsConnected) {
        return $clientInfo.ScpClient
    }
    if ($clientInfo.ScpClient) {
        try { $clientInfo.ScpClient.Dispose() } catch { }
    }

    $scpClient = [Renci.SshNet.ScpClient]::new($clientInfo.Client.ConnectionInfo)
    # Verify host key on the SCP sub-connection matches the verified SSH session key
    $verifiedFp = $clientInfo.Fingerprint
    if ($verifiedFp) {
        $scpClient.add_HostKeyReceived({
            param($sender, $e)
            $fp = ConvertTo-SSHFingerprint -KeyData $e.HostKey -Algorithm SHA256
            $e.CanTrust = ($fp -eq $verifiedFp)
        })
    }
    $scpClient.Connect()
    $clientInfo.ScpClient = $scpClient
    return $scpClient
}

function Disconnect-SSHSessionInternal {
    <#
    .SYNOPSIS
        Disconnects and disposes all internal clients for a session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$SessionId
    )

    $clientInfo = Resolve-SSHClient -SessionId $SessionId
    if (-not $clientInfo) { return }

    if ($clientInfo.SftpClient) {
        try { $clientInfo.SftpClient.Disconnect(); $clientInfo.SftpClient.Dispose() } catch { }
        $clientInfo.SftpClient = $null
    }
    if ($clientInfo.ScpClient) {
        try { $clientInfo.ScpClient.Disconnect(); $clientInfo.ScpClient.Dispose() } catch { }
        $clientInfo.ScpClient = $null
    }
    if ($clientInfo.Client) {
        try { $clientInfo.Client.Disconnect(); $clientInfo.Client.Dispose() } catch { }
        $clientInfo.Client = $null
    }

    # Update the session info object
    if ($script:SSHSessions.ContainsKey($SessionId)) {
        $script:SSHSessions[$SessionId].Connected = $false
    }
}
