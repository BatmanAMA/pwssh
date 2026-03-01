# Remove-SSHKnownHost

## SYNOPSIS

Removes entries from the SSH known_hosts file.

## SYNTAX

```
Remove-SSHKnownHost [-HostName] <String[]> [-Port <Int32>] [-Path <String>]
    [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Removes one or more host key entries from the known_hosts file by hostname. Uses exclusive file locking for safe concurrent access.

## EXAMPLES

### Example 1: Remove a host

```powershell
Remove-SSHKnownHost -HostName 'old-server.example.com'
```

### Example 2: Remove a host on a non-standard port

```powershell
Remove-SSHKnownHost -HostName '10.0.0.1' -Port 2222
```

## PARAMETERS

### -HostName

The hostname to remove.

| | |
|---|---|
| Type | String[] |
| Position | 0 |
| Required | True |
| Pipeline Input | True (ByValue, ByPropertyName) |

### -Port

The SSH port. Defaults to 22.

| | |
|---|---|
| Type | Int32 |
| Required | False |
| Default | 22 |

### -Path

Path to the known_hosts file. Defaults to `~/.ssh/known_hosts`.

| | |
|---|---|
| Type | String |
| Required | False |
| Default | ~/.ssh/known_hosts |

## RELATED LINKS

- [Add-SSHKnownHost](Add-SSHKnownHost.md)
- [Get-SSHKnownHost](Get-SSHKnownHost.md)
