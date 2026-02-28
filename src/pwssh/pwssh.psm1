#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

# Load SSH.NET assembly
$libPath = Join-Path $PSScriptRoot 'lib' 'Renci.SshNet.dll'
if (Test-Path $libPath) {
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
$privatePath = Join-Path $PSScriptRoot 'Private'
if (Test-Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter '*.ps1' | ForEach-Object {
        . $_.FullName
    }
}

# Compile and load the PwSSH.Crypto C# engine
Initialize-SSHCrypto

# Load public functions
$publicPath = Join-Path $PSScriptRoot 'Public'
if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -Recurse | ForEach-Object {
        . $_.FullName
    }
}

# Initialize module state
$script:SSHSessions     = [System.Collections.Generic.Dictionary[int, SSHSessionInfo]]::new()
$script:SSHPortForwards  = [System.Collections.Generic.Dictionary[int, SSHPortForward]]::new()
$script:NextSessionId    = 1
$script:NextForwardId    = 1

# Module cleanup — disconnect all sessions on module removal
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    foreach ($session in $script:SSHSessions.Values) {
        try { $session.Disconnect() } catch { }
    }
    $script:SSHSessions.Clear()
    $script:SSHPortForwards.Clear()
}
