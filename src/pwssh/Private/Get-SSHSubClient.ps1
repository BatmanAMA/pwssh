function Get-SSHSubClient {
    <#
    .SYNOPSIS
        Returns the session's connected SFTP or SCP client, creating it on demand.
    .DESCRIPTION
        SSH.NET's SftpClient and ScpClient open their own transport connection. That
        connection is pinned to the exact host key the session accepted when it was
        established, so it cannot be redirected to a different server.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [SSHSessionInfo]$Session,

        [Parameter(Mandatory)]
        [ValidateSet('Sftp', 'Scp')]
        [string]$Type
    )

    $propName = "Internal${Type}Client"
    $existing = $Session.$propName
    if ($existing -and $existing.IsConnected) { return $existing }
    if ($existing) {
        try { $existing.Dispose() } catch { }
        $Session.$propName = $null
    }

    if (-not $Session.HostKey) {
        throw "Session $($Session.SessionId) has no recorded host key; refusing to open an unverified $($Type.ToUpper()) connection."
    }

    $connInfo = $Session.InternalSession.ConnectionInfo
    $client = switch ($Type) {
        'Sftp' { [Renci.SshNet.SftpClient]::new($connInfo) }
        'Scp'  { [Renci.SshNet.ScpClient]::new($connInfo) }
    }

    $verifier = [PwSSH.HostKeyVerifier]::new()
    $verifier.Mode = [PwSSH.HostKeyMode]::Pinned
    $verifier.Host = $Session.ComputerName
    $verifier.Port = $Session.Port
    $verifier.PinnedKey = $Session.HostKey
    $verifier.Attach($client)

    try {
        $client.Connect()
    }
    catch {
        try { $client.Dispose() } catch { }
        if ($verifier.Error) { throw $verifier.Error }
        throw
    }

    if (-not ($verifier.Invoked -and $verifier.Trusted)) {
        try { $client.Dispose() } catch { }
        throw "Host key verification did not complete for $($Session.ComputerName):$($Session.Port)."
    }

    $Session.$propName = $client
    return $client
}
