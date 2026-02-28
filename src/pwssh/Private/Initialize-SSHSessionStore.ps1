function Initialize-SSHSessionStore {
    <#
    .SYNOPSIS
        Initializes the module-scoped session and port-forward stores.
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
