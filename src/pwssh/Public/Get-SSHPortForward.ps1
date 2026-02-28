function Get-SSHPortForward {
    <#
    .SYNOPSIS
        Lists active SSH port forwards.
    .DESCRIPTION
        Returns SSHPortForward objects for active tunnels.
    .PARAMETER ForwardId
        One or more forward IDs to retrieve.
    .PARAMETER SessionId
        Filter by session ID.
    .EXAMPLE
        Get-SSHPortForward
    .EXAMPLE
        Get-SSHPortForward -SessionId 1
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    [OutputType([SSHPortForward])]
    param(
        [Parameter(Position = 0, ParameterSetName = 'ById')]
        [int[]]$ForwardId,

        [Parameter(ParameterSetName = 'BySession')]
        [int]$SessionId
    )

    begin {
        Initialize-SSHSessionStore
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'ById' {
                foreach ($id in $ForwardId) {
                    if ($script:SSHPortForwards.ContainsKey($id)) {
                        $script:SSHPortForwards[$id]
                    }
                    else {
                        Write-Error "Port forward $id not found."
                    }
                }
            }
            'BySession' {
                $script:SSHPortForwards.Values | Where-Object { $_.SessionId -eq $SessionId }
            }
            default {
                $script:SSHPortForwards.Values
            }
        }
    }
}
