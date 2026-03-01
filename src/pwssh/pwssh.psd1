@{
    RootModule        = 'pwssh.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '23481e80-8ebc-4dd9-a5ae-68ca4deda202'
    Author            = 'BatmanAMA'
    CompanyName       = 'Community'
    Copyright         = '(c) 2025 BatmanAMA. MIT License.'
    Description       = 'A pure .NET/PowerShell SSH client module built on SSH.NET. Provides session management, command execution, SCP/SFTP file transfer, port forwarding, and key management.'

    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredAssemblies = @()  # Loaded dynamically in psm1

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

        # Key management (pure .NET — no ssh-keygen required)
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

    HelpInfoURI = 'https://github.com/BatmanAMA/pwssh/tree/main/docs'

    PrivateData = @{
        PSData = @{
            Tags         = @('SSH', 'SCP', 'SFTP', 'RemoteAccess', 'Networking', 'Linux', 'CrossPlatform')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/BatmanAMA/pwssh'
            ReleaseNotes = 'Initial release — SSH sessions, command execution, SCP/SFTP, port forwarding, key management.'
        }
    }
}
