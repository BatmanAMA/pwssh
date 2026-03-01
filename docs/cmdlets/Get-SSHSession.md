# Get-SSHSession

## SYNOPSIS

Lists active SSH sessions.

## SYNTAX

```
Get-SSHSession [[-SessionId] <Int32[]>] [-ComputerName <String>] [-Active] [<CommonParameters>]
```

## DESCRIPTION

Returns one or more SSHSessionInfo objects from the session store. Without parameters, returns all sessions.

## EXAMPLES

### Example 1: List all sessions

```powershell
Get-SSHSession
```

### Example 2: Get specific sessions

```powershell
Get-SSHSession -SessionId 1, 2
```

### Example 3: Filter by hostname wildcard

```powershell
Get-SSHSession -ComputerName 'web*' -Active
```

## PARAMETERS

### -SessionId

One or more session IDs to retrieve.

| | |
|---|---|
| Type | Int32[] |
| Position | 0 |
| Required | False |
| Pipeline Input | True (ByValue, ByPropertyName) |

### -ComputerName

Filter sessions by computer name. Supports wildcards.

| | |
|---|---|
| Type | String |
| Required | False |

### -Active

Only return sessions that are currently connected.

| | |
|---|---|
| Type | SwitchParameter |
| Required | False |

## OUTPUTS

**SSHSessionInfo**

## RELATED LINKS

- [New-SSHSession](New-SSHSession.md)
- [Remove-SSHSession](Remove-SSHSession.md)
