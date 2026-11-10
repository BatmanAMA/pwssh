function Get-SSHKnownHost {
    <#
    .SYNOPSIS
        Lists entries from the SSH known_hosts file.
    .DESCRIPTION
        Parses an OpenSSH known_hosts file and returns SSHKnownHost objects, one per
        host name on each line. Hashed entries (|1|salt|hash), @revoked and
        @cert-authority markers, per-host [host]:port syntax and trailing comments
        are understood.
    .PARAMETER Path
        Path to the known_hosts file. Defaults to ~/.ssh/known_hosts.
    .PARAMETER HostName
        Return only entries for this host. Wildcards are matched against the host
        names stored in the file; hashed entries and entries whose stored pattern
        covers the name (for example *.example.com) are matched the way OpenSSH would.
    .PARAMETER Port
        With -HostName, only return entries for this port.
    .EXAMPLE
        Get-SSHKnownHost
    .EXAMPLE
        Get-SSHKnownHost -HostName 'github.com'
    #>
    [CmdletBinding()]
    [OutputType([SSHKnownHost])]
    param(
        [Parameter()]
        [string]$Path,

        [Parameter(Position = 0)]
        [string]$HostName,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    process {
        $filePath = Get-SSHKnownHostsPath -Path $Path

        if (-not (Test-Path -LiteralPath $filePath)) {
            Write-Verbose "Known hosts file not found: $filePath"
            return
        }

        foreach ($parsed in [PwSSH.KnownHostsFile]::Parse($filePath)) {
            $fingerprint = if ($parsed.KeyBlob) { [PwSSH.KnownHostsFile]::Sha256Fingerprint($parsed.KeyBlob) } else { '<invalid>' }

            $hostItems = if ($parsed.IsHashed) { @($parsed.HostField) } else { $parsed.HostField -split ',' | Where-Object { $_ } }

            foreach ($item in $hostItems) {
                $itemHost = $item
                $itemPort = 22
                if (-not $parsed.IsHashed -and $item -match '^(!?)\[([^\]]+)\]:(\d+)$') {
                    $itemHost = $Matches[1] + $Matches[2]
                    $itemPort = [int]$Matches[3]
                }

                if ($HostName) {
                    $single = [PwSSH.KnownHostEntry]::new()
                    $single.HostField = $item
                    if ($Port) {
                        $isMatch = $single.MatchesHost([PwSSH.KnownHostsFile]::FormatHost($HostName, $Port))
                    }
                    else {
                        # No port given: match the name on any port
                        $isMatch = $single.MatchesHost($HostName)
                        if (-not $isMatch -and -not $parsed.IsHashed) {
                            $isMatch = ($itemHost -like $HostName) -or
                                       [PwSSH.KnownHostsFile]::WildcardMatch($itemHost.ToLowerInvariant(), $HostName.ToLowerInvariant())
                        }
                    }
                    if (-not $isMatch) { continue }
                    if ($parsed.IsHashed -and $Port) { $itemPort = $Port }
                }

                $entry = [SSHKnownHost]::new()
                $entry.HostName    = $itemHost
                $entry.Port        = $itemPort
                $entry.KeyType     = $parsed.KeyType
                $entry.KeyData     = $parsed.KeyBase64
                $entry.Fingerprint = $fingerprint
                $entry.Marker      = $parsed.Marker
                $entry.Hashed      = $parsed.IsHashed
                $entry.Comment     = $parsed.Comment
                $entry.Source      = $filePath
                $entry.LineNumber  = $parsed.LineNumber
                $entry
            }
        }
    }
}
