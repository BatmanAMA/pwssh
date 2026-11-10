# Shared bootstrap for the pwssh unit tests.
#
# Dot-source it from a BeforeAll block:
#
#   BeforeAll { . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelper.ps1') }
#
# It loads the module's functions straight into the test scope, so private
# functions and the session stores ($script:SSHSessions, ...) can be reached and
# mocked without InModuleScope. Nothing here needs SSH.NET: unit tests must run
# without the downloaded dependencies. Loading the built module and talking to a
# real server is covered by Tests/Unit/Module.Tests.ps1 and Tests/Integration.

$script:ModuleRoot = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'src') 'pwssh'

# Private functions
Get-ChildItem -LiteralPath (Join-Path $script:ModuleRoot 'Private') -Filter '*.ps1' |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

# C# types (output classes, crypto, known_hosts, host key verifier)
Initialize-SSHCrypto

# Script methods/properties the module attaches to its types
if (-not (Get-TypeData -TypeName SSHSessionInfo)) {
    Update-TypeData -AppendPath (Join-Path (Join-Path $script:ModuleRoot 'Types') 'pwssh.Types.ps1xml')
}

# Public functions
Get-ChildItem -LiteralPath (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

# Module state
$script:SSHSessions     = [System.Collections.Generic.Dictionary[int, SSHSessionInfo]]::new()
$script:SSHPortForwards = [System.Collections.Generic.Dictionary[int, SSHPortForward]]::new()
$script:NextSessionId   = 1
$script:NextForwardId   = 1

function New-TestDirectory {
    # A unique scratch directory under the system temp path
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_test_$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
    $dir
}

function New-TestHostKeyData {
    # Base64 of a well-formed (random) public key blob: string key-type, string data
    param([string]$KeyType = 'ssh-ed25519')

    $ms = [System.IO.MemoryStream]::new()
    [PwSSH.Crypto.SshWireFormat]::WriteString($ms, $KeyType)
    $random = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($random)
    $rng.Dispose()
    [PwSSH.Crypto.SshWireFormat]::WriteBytes($ms, $random)
    [System.Convert]::ToBase64String($ms.ToArray())
}
