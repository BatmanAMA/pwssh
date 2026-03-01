# Release Notes

## 0.1.0 (2025)

Initial release including:

- Session management (`New-SSHSession`, `Get-SSHSession`, `Remove-SSHSession`, `Enter-SSHSession`)
- Command execution (`Invoke-SSHCommand`) with stdout/stderr/exit code capture
- SCP file transfer (`Send-SCPFile`, `Receive-SCPFile`)
- SFTP file transfer (`Send-SFTPFile`, `Receive-SFTPFile`, `Get-SFTPChildItem`)
- Port forwarding (`New-SSHPortForward`, `Get-SSHPortForward`, `Remove-SSHPortForward`) — local, remote, and dynamic (SOCKS)
- Pure .NET key generation (`New-SSHKeyPair`) — Ed25519, RSA, ECDSA without ssh-keygen
- Key utilities (`ConvertTo-SSHPublicKey`, `Get-SSHKeyFingerprint`, `Test-SSHKeyFile`)
- Host key management (`Get-SSHHostKey`, `Get-SSHKnownHost`, `Add-SSHKnownHost`, `Remove-SSHKnownHost`)
- TOFU host key verification with known_hosts support
- Weak algorithm stripping (3DES-CBC, Blowfish, Arcfour, HMAC-MD5, DH Group1)
- Assembly integrity verification via SHA-256 hash check
- Memory safety hardening — credential byte arrays pinned and wiped, plaintext references nulled
- Cross-platform support: Windows PowerShell 5.1, PowerShell 7.4+, Linux, macOS
