# Get-SSHHostKey

## SYNOPSIS

Retrieves the SSH host key from a remote server.

## SYNTAX

```
Get-SSHHostKey [-ComputerName] <String[]> [-Port <Int32>] [-Timeout <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Connects to the specified host and retrieves its public host key information without establishing a full session.

## EXAMPLES

### Example 1: Get a host key

```powershell
Get-SSHHostKey -ComputerName github.com
```

### Example 2: Query multiple hosts via pipeline

```powershell
'server1', 'server2' | Get-SSHHostKey
```

## PARAMETERS

### -ComputerName

The hostname or IP address to query.

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

### -Timeout

Connection timeout in seconds. Defaults to 10.

| | |
|---|---|
| Type | Int32 |
| Required | False |
| Default | 10 |

## OUTPUTS

**SSHHostKey**

## RELATED LINKS

- [Add-SSHKnownHost](Add-SSHKnownHost.md)
- [Get-SSHKnownHost](Get-SSHKnownHost.md)
