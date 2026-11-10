function Get-SSHTargetSession {
    <#
    .SYNOPSIS
        Looks up a session by ID and checks that it is still connected.
    .DESCRIPTION
        Writes a non-terminating error and returns nothing when the session is
        unknown or no longer connected.
    #>
    [CmdletBinding()]
    param(
        [int]$SessionId,

        [SSHSessionInfo]$Session
    )

    Initialize-SSHSessionStore

    if (-not $Session) {
        if (-not $script:SSHSessions.ContainsKey($SessionId)) {
            Write-Error "Session $SessionId not found."
            return
        }
        $Session = $script:SSHSessions[$SessionId]
    }

    if (-not $Session.Connected -or -not $Session.InternalSession.IsConnected) {
        Write-Error "Session $($Session.SessionId) is not connected."
        return
    }

    $Session
}
