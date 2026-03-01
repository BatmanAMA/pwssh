# New-SSHSession

## SYNOPSIS

Opens a new SSH session to a remote host.

## SYNTAX

```
New-SSHSession [-ComputerName] <String[]> [-Port <Int32>] [-Credential <PSCredential>]
    [-UserName <String>] [-AcceptKey] [-StrictHostKeyChecking <String>]
    [-ConnectionTimeout <Int32>] [-KeepAliveInterval <Int32>] [<CommonParameters>]

New-SSHSession [-ComputerName] <String[]> [-Port <Int32>] [-KeyFile <String>]
    [-KeyPassphrase <SecureString>] [-UserName <String>] [-AcceptKey]
    [-StrictHostKeyChecking <String>] [-ConnectionTimeout <Int32>]
    [-KeepAliveInterval <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Creates an SSH connection using password, key-based, or default key authentication.
Returns an SSHSessionInfo object representing the session.

Host key verification uses TOFU (Trust On First Use) by default:

- Known host with matching key: trusted automatically
- Known host with CHANGED key: connection refused (MITM protection)
- Unknown host: prompts to accept (or use `-AcceptKey` to auto-accept)

## EXAMPLES

### Example 1: Connect with a credential

```powershell
New-SSHSession -ComputerName server01 -Credential (Get-Credential)
```

### Example 2: Connect with user@host:port syntax and a key file

```powershell
New-SSHSession -ComputerName root@192.168.1.100:2222 -KeyFile ~/.ssh/id_ed25519
```

### Example 3: Auto-accept host key

```powershell
$session = New-SSHSession server01 -UserName admin -AcceptKey
```

### Example 4: Connect to multiple hosts

```powershell
'web01', 'web02', 'web03' | New-SSHSession -Credential $cred -AcceptKey
```

## PARAMETERS

### -ComputerName

The hostname or IP address to connect to. Supports `user@host:port` syntax.

| | |
|---|---|
| Type | String[] |
| Position | 0 |
| Required | True |
| Pipeline Input | True (ByValue, ByPropertyName) |
| Aliases | HostName, Host, Server, Target |

### -Port

The SSH port. Defaults to 22.

| | |
|---|---|
| Type | Int32 |
| Required | False |
| Default | 22 |

### -Credential

A PSCredential for password-based authentication. The username from the credential is used if `-UserName` is not specified.

| | |
|---|---|
| Type | PSCredential |
| Required | False |

### -UserName

The username for the SSH connection. Overrides the credential username.

| | |
|---|---|
| Type | String |
| Required | False |

### -KeyFile

Path to a private key file for public key authentication.

| | |
|---|---|
| Type | String |
| Required | False |
| Aliases | Identity, IdentityFile, KeyPath |

### -KeyPassphrase

Passphrase for the private key file as a SecureString.

| | |
|---|---|
| Type | SecureString |
| Required | False |

### -AcceptKey

Automatically accept and trust the host key without prompting. Equivalent to OpenSSH `StrictHostKeyChecking=no`.

| | |
|---|---|
| Type | SwitchParameter |
| Required | False |

### -StrictHostKeyChecking

Host key verification mode:

- `Ask` (default) — prompt for unknown hosts, reject changed keys
- `Yes` — reject both unknown and changed keys
- `No` — accept all keys (same as `-AcceptKey`)

| | |
|---|---|
| Type | String |
| Required | False |
| Default | Ask |

### -ConnectionTimeout

Connection timeout in seconds. Defaults to 30.

| | |
|---|---|
| Type | Int32 |
| Required | False |
| Default | 30 |

### -KeepAliveInterval

Keep-alive interval in seconds. Defaults to 15. Set to 0 to disable.

| | |
|---|---|
| Type | Int32 |
| Required | False |
| Default | 15 |

## OUTPUTS

**SSHSessionInfo**

## RELATED LINKS

- [Get-SSHSession](Get-SSHSession.md)
- [Remove-SSHSession](Remove-SSHSession.md)
- [Enter-SSHSession](Enter-SSHSession.md)
- [Invoke-SSHCommand](Invoke-SSHCommand.md)
