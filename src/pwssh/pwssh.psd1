@{
    RootModule        = 'pwssh.psm1'
    ModuleVersion     = '0.2.0'
    GUID              = '23481e80-8ebc-4dd9-a5ae-68ca4deda202'
    Author            = 'BatmanAMA'
    CompanyName       = 'Community'
    Copyright         = '(c) 2025 BatmanAMA. MIT License.'
    Description       = 'An SSH client module for PowerShell built on SSH.NET: sessions, command execution, SCP/SFTP file transfer, port forwarding, OpenSSH-compatible key generation and known_hosts verification.'

    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    # SSH.NET and its dependencies are loaded by pwssh.psm1 from lib/desktop or lib/core
    RequiredAssemblies = @()

    FormatsToProcess  = @('Formats/pwssh.Format.ps1xml')
    TypesToProcess    = @('Types/pwssh.Types.ps1xml')

    FunctionsToExport = @(
        # Session management
        'New-SSHSession'
        'Get-SSHSession'
        'Remove-SSHSession'
        'Enter-SSHSession'

        # Command execution
        'Invoke-SSHCommand'

        # SCP file transfer
        'Send-SCPFile'
        'Receive-SCPFile'

        # SFTP file transfer
        'Send-SFTPFile'
        'Receive-SFTPFile'
        'Get-SFTPChildItem'

        # Port forwarding
        'New-SSHPortForward'
        'Get-SSHPortForward'
        'Remove-SSHPortForward'

        # Key management (implemented in .NET, ssh-keygen is not required)
        'New-SSHKeyPair'
        'ConvertTo-SSHPublicKey'
        'Get-SSHKeyFingerprint'
        'Test-SSHKeyFile'

        # Host key management
        'Get-SSHHostKey'
        'Get-SSHKnownHost'
        'Add-SSHKnownHost'
        'Remove-SSHKnownHost'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('SSH', 'SCP', 'SFTP', 'RemoteAccess', 'Networking', 'Linux', 'CrossPlatform')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/BatmanAMA/pwssh'
            ReleaseNotes = 'See CHANGELOG.md at https://github.com/BatmanAMA/pwssh/blob/main/CHANGELOG.md'
        }
    }
}
