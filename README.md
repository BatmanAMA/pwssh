# pwssh

pwssh is a pure .NET/PowerShell SSH client module built on [SSH.NET](https://github.com/sshnet/SSH.NET). No external binaries required.

[![CI](https://github.com/BatmanAMA/pwssh/actions/workflows/ci.yml/badge.svg)](https://github.com/BatmanAMA/pwssh/actions/workflows/ci.yml)

## Documentation

Check out our **[documentation](https://github.com/BatmanAMA/pwssh/tree/main/docs/)** for per-cmdlet reference and examples.

## Features

- Session management with TOFU host key verification
- Command execution with stdout/stderr/exit code capture
- SCP and SFTP file transfers
- Local, remote, and dynamic (SOCKS) port forwarding
- Interactive shell sessions
- Pure .NET key generation (Ed25519, RSA, ECDSA) — no `ssh-keygen` required
- Known hosts management (OpenSSH-compatible `known_hosts`)
- Cross-platform: Windows PowerShell 5.1, PowerShell 7.4+, Linux, macOS

## Installation

### Gallery

```powershell
Install-Module pwssh -Scope CurrentUser
```

### Source

```powershell
git clone 'https://github.com/BatmanAMA/pwssh.git'
Set-Location .\pwssh
.\build.ps1 -Task Build
Import-Module .\output\pwssh\pwssh.psd1
```

## Usage

### Connect with a key

```powershell
Import-Module pwssh
$session = New-SSHSession -ComputerName server01 -UserName admin -KeyFile ~/.ssh/id_ed25519
```

### Connect with a password

```powershell
$cred = Get-Credential
$session = New-SSHSession -ComputerName server01 -Credential $cred
```

### Run a command

```powershell
$result = Invoke-SSHCommand -SessionId $session.SessionId -Command 'uname -a'
$result.Output    # stdout
$result.ExitCode  # 0 on success
```

### Upload a file via SFTP

```powershell
Send-SFTPFile -SessionId $session.SessionId -LocalPath ./deploy.tar.gz -RemotePath /tmp/deploy.tar.gz
```

### Download a file via SFTP

```powershell
Receive-SFTPFile -SessionId $session.SessionId -RemotePath /var/log/app.log -LocalPath ./app.log
```

### Port forwarding

```powershell
# Forward local port 8080 to remote service on port 80
New-SSHPortForward -SessionId $session.SessionId -Type Local -BoundHost localhost -BoundPort 8080 -Host 10.0.0.5 -Port 80
```

### Interactive shell

```powershell
Enter-SSHSession -SessionId $session.SessionId
# Type 'exit' or Ctrl+C to return to local shell
```

### Generate an SSH key pair

```powershell
New-SSHKeyPair -Path ~/.ssh/id_ed25519 -KeyType Ed25519
```

### Disconnect

```powershell
Remove-SSHSession -SessionId $session.SessionId
```

## Security

pwssh applies several hardening measures beyond SSH.NET defaults:

- **TOFU host key verification** — unknown hosts prompt, changed keys are rejected
- **Weak algorithm stripping** — 3DES-CBC, Blowfish, Arcfour, HMAC-MD5, DH Group1 removed from negotiation
- **Assembly integrity** — SHA-256 hash verification of SSH.NET DLL at load time
- **Memory safety** — credential byte arrays are pinned and wiped after use; plaintext string references are nulled immediately
- **Key file permissions** — `chmod 600` on Linux/macOS, restrictive ACLs on Windows

See the [security documentation](https://github.com/BatmanAMA/pwssh/tree/main/docs/SECURITY.md) for details.

## Contributions Welcome!

We would love to incorporate community contributions into this project. If you would like to
contribute code, documentation, tests, or bug reports, please read our [Contribution Guide](https://github.com/BatmanAMA/pwssh/tree/main/docs/CONTRIBUTING.md) to learn more.
