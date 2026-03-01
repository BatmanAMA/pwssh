# pwssh Documentation

## Module: pwssh

**Version:** 0.1.0
**GUID:** 23481e80-8ebc-4dd9-a5ae-68ca4deda202

A pure .NET/PowerShell SSH client module built on SSH.NET.

## Cmdlet Reference

### Session Management

- [New-SSHSession](cmdlets/New-SSHSession.md) — Open a new SSH session
- [Get-SSHSession](cmdlets/Get-SSHSession.md) — List active sessions
- [Remove-SSHSession](cmdlets/Remove-SSHSession.md) — Close and remove sessions
- [Enter-SSHSession](cmdlets/Enter-SSHSession.md) — Interactive shell session

### Command Execution

- [Invoke-SSHCommand](cmdlets/Invoke-SSHCommand.md) — Run commands remotely

### SCP File Transfer

- [Send-SCPFile](cmdlets/Send-SCPFile.md) — Upload via SCP
- [Receive-SCPFile](cmdlets/Receive-SCPFile.md) — Download via SCP

### SFTP File Transfer

- [Send-SFTPFile](cmdlets/Send-SFTPFile.md) — Upload via SFTP
- [Receive-SFTPFile](cmdlets/Receive-SFTPFile.md) — Download via SFTP
- [Get-SFTPChildItem](cmdlets/Get-SFTPChildItem.md) — List remote directory

### Port Forwarding

- [New-SSHPortForward](cmdlets/New-SSHPortForward.md) — Create SSH tunnel
- [Get-SSHPortForward](cmdlets/Get-SSHPortForward.md) — List active tunnels
- [Remove-SSHPortForward](cmdlets/Remove-SSHPortForward.md) — Stop and remove tunnels

### Key Management

- [New-SSHKeyPair](cmdlets/New-SSHKeyPair.md) — Generate SSH key pair (pure .NET)
- [ConvertTo-SSHPublicKey](cmdlets/ConvertTo-SSHPublicKey.md) — Extract public key from private key
- [Get-SSHKeyFingerprint](cmdlets/Get-SSHKeyFingerprint.md) — Show key fingerprint
- [Test-SSHKeyFile](cmdlets/Test-SSHKeyFile.md) — Validate SSH key file

### Host Key Management

- [Get-SSHHostKey](cmdlets/Get-SSHHostKey.md) — Retrieve remote host key
- [Get-SSHKnownHost](cmdlets/Get-SSHKnownHost.md) — List known hosts
- [Add-SSHKnownHost](cmdlets/Add-SSHKnownHost.md) — Add to known hosts
- [Remove-SSHKnownHost](cmdlets/Remove-SSHKnownHost.md) — Remove from known hosts

## Other Documentation

- [Security](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Release Notes](RELEASENOTES.md)
