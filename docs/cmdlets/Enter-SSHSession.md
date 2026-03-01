# Enter-SSHSession

## SYNOPSIS

Enters an interactive SSH shell session.

## SYNTAX

```
Enter-SSHSession [-SessionId] <Int32> [-TerminalType <String>] [-Columns <Int32>]
    [-Rows <Int32>] [<CommonParameters>]

Enter-SSHSession -Session <SSHSessionInfo> [-TerminalType <String>] [-Columns <Int32>]
    [-Rows <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Opens an interactive terminal stream to the remote SSH host. Type `exit` or press Ctrl+C to return to the local shell.

## EXAMPLES

### Example 1: Enter by session ID

```powershell
Enter-SSHSession -SessionId 1
```

### Example 2: Enter via pipeline

```powershell
$s = New-SSHSession server01 -Credential $cred
$s | Enter-SSHSession
```

## PARAMETERS

### -SessionId

The session ID to interact with.

| | |
|---|---|
| Type | Int32 |
| Position | 0 |
| Required | True |

### -Session

An SSHSessionInfo object to interact with.

| | |
|---|---|
| Type | SSHSessionInfo |
| Required | True |
| Pipeline Input | True (ByValue) |

### -TerminalType

Terminal type to request. Defaults to `xterm-256color`.

| | |
|---|---|
| Type | String |
| Required | False |
| Default | xterm-256color |

### -Columns

Terminal width in columns. Defaults to current console width.

| | |
|---|---|
| Type | Int32 |
| Required | False |

### -Rows

Terminal height in rows. Defaults to current console height.

| | |
|---|---|
| Type | Int32 |
| Required | False |

## RELATED LINKS

- [New-SSHSession](New-SSHSession.md)
- [Invoke-SSHCommand](Invoke-SSHCommand.md)
