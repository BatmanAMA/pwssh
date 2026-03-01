# Get-SSHKnownHost

## SYNOPSIS

Lists entries from the SSH known_hosts file.

## SYNTAX

```
Get-SSHKnownHost [[-HostName] <String>] [-Path <String>] [<CommonParameters>]
```

## DESCRIPTION

Parses the OpenSSH `known_hosts` file and returns SSHKnownHost objects.

## EXAMPLES

### Example 1: List all known hosts

```powershell
Get-SSHKnownHost
```

### Example 2: Filter by hostname

```powershell
Get-SSHKnownHost -HostName 'github.com'
```

## PARAMETERS

### -HostName

Filter by hostname. Supports wildcards.

| | |
|---|---|
| Type | String |
| Position | 0 |
| Required | False |

### -Path

Path to the known_hosts file. Defaults to `~/.ssh/known_hosts`.

| | |
|---|---|
| Type | String |
| Required | False |
| Default | ~/.ssh/known_hosts |

## OUTPUTS

**SSHKnownHost**

## RELATED LINKS

- [Add-SSHKnownHost](Add-SSHKnownHost.md)
- [Remove-SSHKnownHost](Remove-SSHKnownHost.md)
- [Get-SSHHostKey](Get-SSHHostKey.md)
