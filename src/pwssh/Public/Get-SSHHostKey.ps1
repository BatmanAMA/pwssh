function Get-SSHHostKey {
    <#
    .SYNOPSIS
        Retrieves the SSH host key from a remote server.
    .DESCRIPTION
        Connects to the specified host and retrieves its public host key information
        without establishing a full session.
    .PARAMETER ComputerName
        The hostname or IP address to query.
    .PARAMETER Port
        The SSH port. Defaults to 22.
    .PARAMETER Timeout
        Connection timeout in seconds. Defaults to 10.
    .EXAMPLE
        Get-SSHHostKey -ComputerName github.com
    .EXAMPLE
        'server1','server2' | Get-SSHHostKey
    #>
    [CmdletBinding()]
    [OutputType([SSHHostKey])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('HostName', 'Host')]
        [string[]]$ComputerName,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 22,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$Timeout = 10
    )

    process {
        foreach ($target in $ComputerName) {
            $parsed = Resolve-SSHHostName -Target $target -DefaultPort $Port
            $hostName = $parsed.ComputerName
            $hostPort = $parsed.Port

            try {
                $connInfo = [Renci.SshNet.ConnectionInfo]::new(
                    $hostName,
                    $hostPort,
                    'none',
                    [Renci.SshNet.AuthenticationMethod[]]@(
                        [Renci.SshNet.NoneAuthenticationMethod]::new('none')
                    )
                )
                $connInfo.Timeout = [timespan]::FromSeconds($Timeout)

                $hostKeyInfo = $null
                $client = [Renci.SshNet.SshClient]::new($connInfo)

                $client.add_HostKeyReceived({
                    param($sender, $e)
                    $hostKeyInfo = [SSHHostKey]::new()
                    $hostKeyInfo.ComputerName  = $hostName
                    $hostKeyInfo.Port          = $hostPort
                    $hostKeyInfo.KeyType       = $e.HostKeyName
                    $hostKeyInfo.KeyLength     = $e.KeyLength
                    $hostKeyInfo.RawKey        = $e.HostKey
                    $hostKeyInfo.Fingerprint   = ConvertTo-SSHFingerprint -KeyData $e.HostKey -Algorithm SHA256
                    $hostKeyInfo.FingerprintMD5 = ConvertTo-SSHFingerprint -KeyData $e.HostKey -Algorithm MD5
                    $e.CanTrust = $true
                    Set-Variable -Name hostKeyInfo -Value $hostKeyInfo -Scope 1
                })

                try { $client.Connect() } catch { <# Expected to fail auth #> }
                finally { $client.Dispose() }

                if ($hostKeyInfo) { $hostKeyInfo }
                else { Write-Warning "Could not retrieve host key from ${hostName}:${hostPort}" }
            }
            catch {
                Write-Error "Failed to get host key from ${hostName}:${hostPort}: $_"
            }
        }
    }
}
