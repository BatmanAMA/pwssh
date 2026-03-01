#Requires -Version 5.1
# Use a local preference for module load — does not leak to caller because
# psm1 files run in the module scope, but be explicit with try/catch below.
$script:ErrorActionPreference = 'Stop'

# Load SSH.NET assembly with integrity verification
$libPath = Join-Path $PSScriptRoot 'lib' 'Renci.SshNet.dll'
$libHashPath = Join-Path $PSScriptRoot 'lib' 'Renci.SshNet.dll.sha256'
if (Test-Path $libPath) {
    # Verify DLL integrity if hash file is present
    if (Test-Path $libHashPath) {
        $expectedHash = ([System.IO.File]::ReadAllText($libHashPath)).Trim().ToUpperInvariant()
        $actualHash = (Get-FileHash -Path $libPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($expectedHash -ne $actualHash) {
            throw "pwssh: Renci.SshNet.dll integrity check FAILED. Expected SHA256: $expectedHash, Got: $actualHash. The assembly may have been tampered with."
        }
    }
    else {
        Write-Warning "pwssh: No integrity hash file found at $libHashPath. DLL loaded without verification. Run build.ps1 to generate the hash file."
    }
    try {
        Add-Type -Path $libPath -ErrorAction Stop
    }
    catch [System.Reflection.ReflectionTypeLoadException] {
        # Assembly already loaded — safe to ignore
    }
}
else {
    Write-Warning "pwssh: Renci.SshNet.dll not found at $libPath. Run build.ps1 to download dependencies."
}

# Load classes (order matters — no circular dependencies)
$classFiles = @(
    'SSHHostKey'
    'SSHKnownHost'
    'SSHCommandResult'
    'SSHPortForward'
    'SSHSession'
)
foreach ($class in $classFiles) {
    . (Join-Path $PSScriptRoot 'Classes' "$class.ps1")
}

# Load private functions (excluding CSharp directory which is compiled separately)
# Sort by name for deterministic load order across platforms
$privatePath = Join-Path $PSScriptRoot 'Private'
if (Test-Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }
}

# Compile and load the PwSSH.Crypto C# engine
Initialize-SSHCrypto

# Load public functions (sorted for deterministic load order)
$publicPath = Join-Path $PSScriptRoot 'Public'
if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }
}

# Initialize module state
$script:SSHSessions     = [System.Collections.Generic.Dictionary[int, SSHSessionInfo]]::new()
$script:SSHClients      = [System.Collections.Generic.Dictionary[int, hashtable]]::new()  # SessionId -> @{ Client; SftpClient; ScpClient; Fingerprint }
$script:SSHPortForwards  = [System.Collections.Generic.Dictionary[int, SSHPortForward]]::new()
$script:NextSessionId    = 1
$script:NextForwardId    = 1

# Module cleanup — disconnect all sessions on module removal
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    foreach ($id in @($script:SSHClients.Keys)) {
        try { Disconnect-SSHSessionInternal -SessionId $id } catch { }
    }
    $script:SSHSessions.Clear()
    $script:SSHClients.Clear()
    $script:SSHPortForwards.Clear()
}
