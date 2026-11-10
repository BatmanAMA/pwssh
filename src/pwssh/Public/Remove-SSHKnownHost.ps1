function Remove-SSHKnownHost {
    <#
    .SYNOPSIS
        Removes entries from the SSH known_hosts file.
    .DESCRIPTION
        Removes every line of the known_hosts file that applies to the given host and
        port, including hashed entries (like ssh-keygen -R). @revoked and
        @cert-authority lines are kept. The file is replaced atomically.
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
        [ValidateRange(1, 65535)]
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
        if (-not (Test-Path -LiteralPath $filePath)) {
            Write-Warning "Known hosts file not found: $filePath"
            return
        }

        $specs = $allHostsToRemove | ForEach-Object { [PwSSH.KnownHostsFile]::FormatHost($_, $Port) }
        $lines = [System.IO.File]::ReadAllLines($filePath)
        $newLines = [System.Collections.Generic.List[string]]::new()
        $removed = 0

        foreach ($line in $lines) {
            $shouldRemove = $false

            $entry = [PwSSH.KnownHostsFile]::ParseLine($line)
            if ($entry -and -not $entry.Marker) {
                foreach ($spec in $specs) {
                    if ($entry.MatchesHost($spec)) { $shouldRemove = $true; break }
                }
            }

            if ($shouldRemove -and $PSCmdlet.ShouldProcess($line, 'Remove known host entry')) {
                $removed++
            }
            else {
                $newLines.Add($line)
            }
        }

        if ($removed -eq 0) {
            Write-Verbose "No matching entries in $filePath"
            return
        }

        # Write a sibling temp file and swap it in, so a crash cannot truncate known_hosts
        $tempPath = "$filePath.$([guid]::NewGuid().ToString('N')).tmp"
        try {
            $text = if ($newLines.Count) { ($newLines -join "`n") + "`n" } else { '' }
            [System.IO.File]::WriteAllText($tempPath, $text, [System.Text.UTF8Encoding]::new($false))
            if (-not (Test-SSHIsWindows)) {
                & chmod --reference=$filePath $tempPath 2>$null
                if ($LASTEXITCODE -ne 0) { & chmod 600 $tempPath 2>$null }
            }
            [System.IO.File]::Replace($tempPath, $filePath, [NullString]::Value)
        }
        finally {
            if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force }
        }
        Write-Verbose "Removed $removed entries from $filePath"
    }
}
