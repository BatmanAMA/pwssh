function Initialize-SSHSessionStore {
    <#
    .SYNOPSIS
        Creates the module-scoped session and port forward stores if they do not
        exist yet.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:SSHSessions) {
        $script:SSHSessions = [System.Collections.Generic.Dictionary[int, SSHSessionInfo]]::new()
        $script:NextSessionId = 1
    }
    if (-not $script:SSHPortForwards) {
        $script:SSHPortForwards = [System.Collections.Generic.Dictionary[int, SSHPortForward]]::new()
        $script:NextForwardId = 1
    }
}
