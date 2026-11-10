function Get-SSHHostKey {
    <#
    .SYNOPSIS
        Retrieves the SSH host key a server presents.
    .DESCRIPTION
        Connects to the host, records the host key it offers and aborts the connection
        before authentication. Nothing is sent to the server beyond the key exchange.
        known_hosts and the ssh config file are not read.

        The key is not verified. It is whatever answered at that address, which may be
        an attacker. Compare the fingerprint with one obtained through a trusted
        channel before adding it to known_hosts.
    .PARAMETER ComputerName
        One or more host names or IP addresses to query. Supports host:port syntax,
        which takes precedence over -Port. Accepts pipeline input. Aliases: HostName,
        Host.
    .PARAMETER Port
        The SSH port. Defaults to 22.
    .PARAMETER Timeout
        Connection timeout in seconds, from 1 to 60. Defaults to 10.
    .EXAMPLE
        Get-SSHHostKey -ComputerName server01 | Format-List ComputerName, KeyType, Fingerprint

        Shows the key type and SHA256 fingerprint the server presents, so that they
        can be compared with the values published by its administrator.
    .EXAMPLE
        $key = Get-SSHHostKey -ComputerName server01
        if ($key.Fingerprint -eq 'SHA256:<fingerprint from a trusted source>') {
            $key | Add-SSHKnownHost
        }

        Adds the key to known_hosts only if its fingerprint matches the one obtained
        through a trusted channel.
    .EXAMPLE
        'server1', 'server2:2222' | Get-SSHHostKey

        Queries several hosts from the pipeline.
    .OUTPUTS
        SSHHostKey
        Properties: ComputerName, Port, KeyType, KeyLength, Fingerprint (SHA256),
        FingerprintMD5 and RawKey.
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
            $hostName = $target
            $hostPort = $Port
            try {
                if (-not ('Renci.SshNet.SshClient' -as [type])) {
                    throw 'SSH.NET is not loaded. Run build.ps1 to download the module dependencies.'
                }

                $parsed = Resolve-SSHHostName -Target $target -DefaultPort $Port
                $hostName = $parsed.ComputerName
                $hostPort = $parsed.Port

                $connInfo = [Renci.SshNet.ConnectionInfo]::new(
                    $hostName,
                    $hostPort,
                    'none',
                    [Renci.SshNet.AuthenticationMethod[]]@(
                        [Renci.SshNet.NoneAuthenticationMethod]::new('none')
                    )
                )
                $connInfo.Timeout = [timespan]::FromSeconds($Timeout)

                $client = [Renci.SshNet.SshClient]::new($connInfo)
                $verifier = [PwSSH.HostKeyVerifier]::new()
                $verifier.Mode = [PwSSH.HostKeyMode]::Capture
                $verifier.Host = $hostName
                $verifier.Port = $hostPort
                $verifier.Attach($client)

                $connectError = $null
                try { $client.Connect() }
                catch { $connectError = $_ }   # expected: the verifier refuses the key
                finally { $client.Dispose() }

                if (-not $verifier.KeyBlob) {
                    $reason = if ($connectError) { $connectError.Exception.Message } else { 'no host key was offered' }
                    throw $reason
                }

                $info = [SSHHostKey]::new()
                $info.ComputerName = $hostName
                $info.Port         = $hostPort
                $info.KeyType      = $verifier.KeyType
                $info.KeyLength    = $verifier.KeyLength
                $info.RawKey       = $verifier.KeyBlob
                $info.Fingerprint  = $verifier.Fingerprint
                try { $info.FingerprintMD5 = ConvertTo-SSHFingerprint -KeyData $verifier.KeyBlob -Algorithm MD5 }
                catch { $info.FingerprintMD5 = $null }   # MD5 is unavailable in FIPS mode
                $info
            }
            catch {
                Write-Error "Failed to get host key from ${hostName}:${hostPort}: $(Get-SSHErrorMessage $_)"
            }
        }
    }
}
