function Get-SSHPortForward {
    <#
    .SYNOPSIS
        Lists the SSH port forwards created with New-SSHPortForward.
    .DESCRIPTION
        Returns SSHPortForward objects from the module's store. Without parameters,
        all forwards are returned.
    .PARAMETER ForwardId
        One or more forward IDs to retrieve. An error is written for an ID that does
        not exist.
    .PARAMETER SessionId
        Return only the forwards that belong to this session.
    .EXAMPLE
        Get-SSHPortForward
    .EXAMPLE
        Get-SSHPortForward -SessionId 1

        Lists the forwards carried by session 1.
    .OUTPUTS
        SSHPortForward
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
