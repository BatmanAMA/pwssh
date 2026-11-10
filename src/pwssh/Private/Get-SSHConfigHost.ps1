function Get-SSHConfigHost {
    <#
    .SYNOPSIS
        Reads the settings that apply to a host from an OpenSSH client config file.
    .DESCRIPTION
        Supports the subset of ssh_config(5) that maps onto this module: Host blocks
        (with * ? wildcards and ! negation) and the HostName, User, Port and
        IdentityFile keywords. As in OpenSSH, the first value obtained for a keyword
        wins, except IdentityFile which accumulates. In IdentityFile values the
        tokens %d (home directory) and %h (the host name as given) are expanded.
        Everything inside a Match block is skipped, and Include directives and
        all other keywords are ignored. Without -Path, ~/.ssh/config is read; the
        system-wide ssh_config is never read.
    .OUTPUTS
        A hashtable with HostName, User, Port and IdentityFile (string[]) keys;
        values are $null / empty when the file does not set them.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$HostName,

        [string]$Path
    )

    $result = @{ HostName = $null; User = $null; Port = $null; IdentityFile = @() }

    if (-not $Path) { $Path = Join-Path (Get-SSHUserDirectory) 'config' }
    else { $Path = Resolve-SSHLocalPath -Path $Path }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $result }

    $target = $HostName.ToLowerInvariant()
    $active = $true     # options before the first Host line apply to every host

    foreach ($rawLine in [System.IO.File]::ReadAllLines($Path)) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }

        # "Keyword value" or "Keyword=value"
        if ($line -notmatch '^(?<key>[A-Za-z0-9]+)\s*(?:=\s*|\s+)(?<value>.+)$') { continue }
        $key = $Matches['key'].ToLowerInvariant()
        $value = $Matches['value'].Trim()

        if ($key -eq 'host') {
            $active = $false
            $matched = $false
            $vetoed = $false
            foreach ($pattern in ($value -split '\s+')) {
                $negated = $pattern.StartsWith('!')
                if ($negated) { $pattern = $pattern.Substring(1) }
                if ([PwSSH.KnownHostsFile]::WildcardMatch($pattern.ToLowerInvariant(), $target)) {
                    if ($negated) { $vetoed = $true } else { $matched = $true }
                }
            }
            $active = $matched -and -not $vetoed
            continue
        }
        if ($key -eq 'match') { $active = $false; continue }
        if (-not $active) { continue }

        $value = $value.Trim('"')
        switch ($key) {
            'hostname' { if (-not $result.HostName) { $result.HostName = $value } }
            'user'     { if (-not $result.User) { $result.User = $value } }
            'port'     {
                $p = 0
                if (-not $result.Port -and [int]::TryParse($value, [ref]$p) -and $p -ge 1 -and $p -le 65535) {
                    $result.Port = $p
                }
            }
            'identityfile' {
                $expanded = $value -replace '%d', $HOME -replace '%h', $HostName
                $result.IdentityFile += $expanded
            }
        }
    }

    return $result
}
