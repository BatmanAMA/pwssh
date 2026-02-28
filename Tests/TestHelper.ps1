# Shared test bootstrap for pwssh Pester tests.
# Dot-source this file in BeforeAll blocks to load classes and private functions.
#
# Usage:
#   BeforeAll { . (Join-Path $PSScriptRoot '..' 'TestHelper.ps1') }

$script:ModuleRoot = Join-Path $PSScriptRoot '..' 'src' 'pwssh'

# Load classes in dependency order
$classFiles = @('SSHHostKey', 'SSHKnownHost', 'SSHCommandResult', 'SSHPortForward', 'SSHSession')
foreach ($class in $classFiles) {
    . (Join-Path $script:ModuleRoot 'Classes' "$class.ps1")
}

# Load all private functions (sorted, excluding CSharp)
Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Private') -Filter '*.ps1' |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

# Compile and load the PwSSH.Crypto C# engine
Initialize-SSHCrypto

# Helper to dot-source a public function by name
function Import-PublicFunction {
    param([string[]]$Name)
    foreach ($n in $Name) {
        . (Join-Path $script:ModuleRoot 'Public' "$n.ps1")
    }
}
