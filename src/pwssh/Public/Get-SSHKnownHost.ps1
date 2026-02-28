function Get-SSHKnownHost {
    <#
    .SYNOPSIS
        Lists entries from the SSH known_hosts file.
    .DESCRIPTION
        Parses the OpenSSH known_hosts file and returns SSHKnownHost objects.
    .PARAMETER Path
        Path to the known_hosts file. Defaults to ~/.ssh/known_hosts.
    .PARAMETER HostName
        Filter by hostname (supports wildcards).
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
        [string]$HostName
    )

    process {
        $filePath = Get-SSHKnownHostsPath -Path $Path

        if (-not (Test-Path $filePath)) {
            Write-Verbose "Known hosts file not found: $filePath"
            return
        }

        $lineNum = 0
        foreach ($line in [System.IO.File]::ReadLines($filePath)) {
            $lineNum++

            # Skip comments and blank lines
            if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) { continue }

            $parts = $line -split '\s+', 3
            if ($parts.Count -lt 3) { continue }

            $hostEntry = $parts[0]
            $keyType   = $parts[1]
            $keyData   = $parts[2]

            # Parse host entry — may be [host]:port or just host
            $parsedHost = $hostEntry
            $parsedPort = 22
            if ($hostEntry -match '^\[([^\]]+)\]:(\d+)$') {
                $parsedHost = $Matches[1]
                $parsedPort = [int]$Matches[2]
            }

            # Handle comma-separated hosts
            $hostNames = $parsedHost -split ','

            foreach ($h in $hostNames) {
                if ($HostName -and $h -notlike $HostName) { continue }

                $entry = [SSHKnownHost]::new()
                $entry.HostName    = $h
                $entry.Port        = $parsedPort
                $entry.KeyType     = $keyType
                $entry.KeyData     = $keyData
                $entry.Source      = $filePath
                $entry.LineNumber  = $lineNum

                # Compute fingerprint
                try {
                    $rawBytes = [System.Convert]::FromBase64String($keyData)
                    $entry.Fingerprint = ConvertTo-SSHFingerprint -KeyData $rawBytes -Algorithm SHA256
                }
                catch {
                    $entry.Fingerprint = '<invalid>'
                }

                $entry
            }
        }
    }
}
