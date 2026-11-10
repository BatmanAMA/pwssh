#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.PSVersion -lt [version]'7.2') {
    throw "pwssh requires Windows PowerShell 5.1 or PowerShell 7.2+. This is PowerShell $($PSVersionTable.PSVersion)."
}

# Private functions (sorted for a deterministic load order)
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
    . $_.FullName
}

# C# types: key handling, known_hosts, host key verification and the output classes.
# These have no dependency on SSH.NET, so key management works without it.
Initialize-SSHCrypto

# SSH.NET and its dependencies. build.ps1 places them in lib/desktop (.NET Framework)
# and lib/core (.NET 6+).
$libEdition = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'desktop' } else { 'core' }
$libDir     = Join-Path (Join-Path $PSScriptRoot 'lib') $libEdition
$sshNetPath = Join-Path $libDir 'Renci.SshNet.dll'

if ('Renci.SshNet.SshClient' -as [type]) {
    Write-Verbose "pwssh: using the SSH.NET assembly already loaded in this session ($([Renci.SshNet.SshClient].Assembly.Location))."
}
elseif (Test-Path -LiteralPath $sshNetPath) {
    # Resolve the bundled dependencies (BouncyCastle, ...) from the same directory.
    [PwSSH.AssemblyResolver]::Register($libDir)
    try {
        if ($libEdition -eq 'core') {
            $bouncyCastle = Join-Path $libDir 'BouncyCastle.Cryptography.dll'
            if (Test-Path -LiteralPath $bouncyCastle) { Add-Type -LiteralPath $bouncyCastle }
        }
        Add-Type -LiteralPath $sshNetPath
    }
    catch {
        $detail = $_.Exception.Message
        if ($_.Exception -is [System.Reflection.ReflectionTypeLoadException]) {
            $detail = ($_.Exception.LoaderExceptions | ForEach-Object { $_.Message } | Select-Object -Unique) -join '; '
        }
        throw "pwssh: failed to load SSH.NET from '$libDir': $detail"
    }
}
else {
    Write-Warning "pwssh: SSH.NET not found in '$libDir'. Run build.ps1 to download the dependencies. Key and known_hosts cmdlets work without it; connections do not."
}

# Public functions
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
    . $_.FullName
}

# Module state
$script:SSHSessions     = [System.Collections.Generic.Dictionary[int, SSHSessionInfo]]::new()
$script:SSHPortForwards = [System.Collections.Generic.Dictionary[int, SSHPortForward]]::new()
$script:NextSessionId   = 1
$script:NextForwardId   = 1

# Disconnect everything when the module is removed
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    foreach ($forward in @($script:SSHPortForwards.Values)) {
        try { $forward.Stop() } catch { }
    }
    foreach ($session in @($script:SSHSessions.Values)) {
        try { $session.Disconnect() } catch { }
    }
    $script:SSHSessions.Clear()
    $script:SSHPortForwards.Clear()
}
