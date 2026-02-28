function Remove-SSHKnownHost {
    <#
    .SYNOPSIS
        Removes entries from the SSH known_hosts file.
    .DESCRIPTION
        Removes one or more host key entries from the known_hosts file by hostname.
    .PARAMETER HostName
        The hostname to remove.
    .PARAMETER Port
        The SSH port. Defaults to 22.
    .PARAMETER Path
        Path to the known_hosts file. Defaults to ~/.ssh/known_hosts.
    .EXAMPLE
        Remove-SSHKnownHost -HostName 'old-server.example.com'
    .EXAMPLE
        Remove-SSHKnownHost -HostName '10.0.0.1' -Port 2222
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$HostName,

        [Parameter()]
        [int]$Port = 22,

        [Parameter()]
        [string]$Path
    )

    begin {
        $filePath = Get-SSHKnownHostsPath -Path $Path
        $allHostsToRemove = [System.Collections.Generic.List[string]]::new()
    }

    process {
        foreach ($h in $HostName) {
            $allHostsToRemove.Add($h)
        }
    }

    end {
        if (-not (Test-Path $filePath)) {
            Write-Warning "Known hosts file not found: $filePath"
            return
        }

        # Use exclusive file lock for the entire read-modify-write to prevent race conditions
        $fs = $null
        try {
            $fs = [System.IO.FileStream]::new(
                $filePath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
            $reader = [System.IO.StreamReader]::new($fs)
            $content = $reader.ReadToEnd()
            $lines = $content -split "`n"

            $newLines = [System.Collections.Generic.List[string]]::new()
            $removed = 0

            foreach ($line in $lines) {
                $shouldRemove = $false

                if (-not [string]::IsNullOrWhiteSpace($line) -and -not $line.TrimStart().StartsWith('#')) {
                    $parts = $line -split '\s+', 3
                    if ($parts.Count -ge 3) {
                        $hostEntry = $parts[0]
                        $parsedHost = $hostEntry
                        $parsedPort = 22
                        if ($hostEntry -match '^\[([^\]]+)\]:(\d+)$') {
                            $parsedHost = $Matches[1]
                            $parsedPort = [int]$Matches[2]
                        }
                        $entryHosts = $parsedHost -split ','

                        foreach ($h in $allHostsToRemove) {
                            if ($entryHosts -contains $h -and $parsedPort -eq $Port) {
                                $shouldRemove = $true
                                break
                            }
                        }
                    }
                }

                if ($shouldRemove) {
                    if ($PSCmdlet.ShouldProcess($line, 'Remove known host entry')) {
                        $removed++
                    }
                    else {
                        $newLines.Add($line)
                    }
                }
                else {
                    $newLines.Add($line)
                }
            }

            # Rewrite the file under the same lock
            $fs.SetLength(0)
            $fs.Position = 0
            $writer = [System.IO.StreamWriter]::new($fs)
            foreach ($l in $newLines) {
                if (-not [string]::IsNullOrWhiteSpace($l)) {
                    $writer.WriteLine($l.TrimEnd("`r"))
                }
            }
            $writer.Flush()
        }
        finally {
            if ($fs) { $fs.Dispose() }
        }
        Write-Verbose "Removed $removed entries from $filePath"
    }
}
