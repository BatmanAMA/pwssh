# Remove-SSHSession

## SYNOPSIS

Closes and removes one or more SSH sessions.

## SYNTAX

```
Remove-SSHSession [-SessionId] <Int32[]> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-SSHSession -Session <SSHSessionInfo[]> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Disconnects the SSH client and removes the session from the session store. Also stops any port forwards attached to the session.

## EXAMPLES

### Example 1: Remove by ID

```powershell
Remove-SSHSession -SessionId 1
```

### Example 2: Remove all sessions via pipeline

```powershell
Get-SSHSession | Remove-SSHSession
```

## PARAMETERS

### -SessionId

One or more session IDs to remove.

| | |
|---|---|
| Type | Int32[] |
| Position | 0 |
| Required | True |
| Pipeline Input | True (ByValue, ByPropertyName) |

### -Session

One or more SSHSessionInfo objects to remove.

| | |
|---|---|
| Type | SSHSessionInfo[] |
| Required | True |
| Pipeline Input | True (ByValue) |

## RELATED LINKS

- [New-SSHSession](New-SSHSession.md)
- [Get-SSHSession](Get-SSHSession.md)
