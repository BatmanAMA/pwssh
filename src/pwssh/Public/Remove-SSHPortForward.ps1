function Remove-SSHPortForward {
    <#
    .SYNOPSIS
        Stops and removes SSH port forwards.
    .DESCRIPTION
        Stops the forwarded port and removes it from the store.
    .PARAMETER ForwardId
        One or more forward IDs to remove.
    .PARAMETER Forward
        One or more SSHPortForward objects to remove.
    .EXAMPLE
        Remove-SSHPortForward -ForwardId 1
    .EXAMPLE
        Get-SSHPortForward -SessionId 1 | Remove-SSHPortForward
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'ById', ValueFromPipelineByPropertyName)]
        [int[]]$ForwardId,

        [Parameter(Mandatory, ParameterSetName = 'ByObject', ValueFromPipeline)]
        [SSHPortForward[]]$Forward
    )

    begin {
        Initialize-SSHSessionStore
    }

    process {
        $targets = switch ($PSCmdlet.ParameterSetName) {
            'ById'     { $ForwardId }
            'ByObject' { $Forward | ForEach-Object { $_.ForwardId } }
        }

        foreach ($id in $targets) {
            if (-not $script:SSHPortForwards.ContainsKey($id)) {
                Write-Error "Port forward $id not found."
                continue
            }

            $fwd = $script:SSHPortForwards[$id]
            if ($PSCmdlet.ShouldProcess("$fwd", 'Stop and remove')) {
                $fwd.Stop()
                $script:SSHPortForwards.Remove($id) | Out-Null
                Write-Verbose "Port forward $id stopped and removed."
            }
        }
    }
}
