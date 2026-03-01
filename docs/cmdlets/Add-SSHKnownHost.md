# Add-SSHKnownHost

## SYNOPSIS

Adds an entry to the SSH known_hosts file.

## SYNTAX

```
Add-SSHKnownHost [-HostName] <String> -KeyType <String> -KeyData <String>
    [-Port <Int32>] [-Path <String>] [<CommonParameters>]

Add-SSHKnownHost -HostKey <SSHHostKey> [-Path <String>] [<CommonParameters>]
```

## DESCRIPTION

Appends a host key entry to the known_hosts file in OpenSSH format. Uses exclusive file locking for safe concurrent access.

## EXAMPLES

### Example 1: Add from a host key scan

```powershell
Get-SSHHostKey github.com | Add-SSHKnownHost
```

### Example 2: Add manually

```powershell
Add-SSHKnownHost -HostName 10.0.0.1 -KeyType ssh-ed25519 -KeyData 'AAAA...'
```

## PARAMETERS

### -HostName

The hostname or IP address.

| | |
|---|---|
| Type | String |
| Position | 0 |
| Required | True |

### -Port

The SSH port. Defaults to 22.

| | |
|---|---|
| Type | Int32 |
| Required | False |
| Default | 22 |

### -KeyType

The key algorithm (e.g., `ssh-ed25519`, `ssh-rsa`).

| | |
|---|---|
| Type | String |
| Required | True |

### -KeyData

The base64-encoded public key data.

| | |
|---|---|
| Type | String |
| Required | True |

### -HostKey

An SSHHostKey object (from `Get-SSHHostKey`).

| | |
|---|---|
| Type | SSHHostKey |
| Required | True |
| Pipeline Input | True (ByValue) |

### -Path

Path to the known_hosts file. Defaults to `~/.ssh/known_hosts`.

| | |
|---|---|
| Type | String |
| Required | False |
| Default | ~/.ssh/known_hosts |

## RELATED LINKS

- [Get-SSHHostKey](Get-SSHHostKey.md)
- [Get-SSHKnownHost](Get-SSHKnownHost.md)
- [Remove-SSHKnownHost](Remove-SSHKnownHost.md)
