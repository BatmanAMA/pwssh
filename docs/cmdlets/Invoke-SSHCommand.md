# Invoke-SSHCommand

## SYNOPSIS

Executes a command on a remote host via SSH.

## SYNTAX

```
Invoke-SSHCommand [-SessionId] <Int32[]> [-Command] <String> [-Timeout <Int32>] [<CommonParameters>]

Invoke-SSHCommand -Session <SSHSessionInfo[]> [-Command] <String> [-Timeout <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Runs one or more commands on the specified SSH session(s) and returns SSHCommandResult objects containing stdout, stderr, and exit code.

## EXAMPLES

### Example 1: Run a command

```powershell
Invoke-SSHCommand -SessionId 1 -Command 'uname -a'
```

### Example 2: Run across multiple sessions and check for failures

```powershell
$result = Invoke-SSHCommand -SessionId 1, 2 -Command 'df -h'
$result | Where-Object { $_.ExitCode -ne 0 }
```

### Example 3: Command with timeout

```powershell
Invoke-SSHCommand -SessionId 1 -Command 'long-running-task' -Timeout 60
```

## PARAMETERS

### -SessionId

The session ID(s) to execute the command on.

| | |
|---|---|
| Type | Int32[] |
| Position | 0 |
| Required | True |

### -Session

SSHSessionInfo object(s) to execute the command on.

| | |
|---|---|
| Type | SSHSessionInfo[] |
| Required | True |
| Pipeline Input | True (ByValue) |

### -Command

The command string to execute on the remote host.

| | |
|---|---|
| Type | String |
| Position | 1 |
| Required | True |

### -Timeout

Command timeout in seconds. Defaults to 0 (no timeout).

| | |
|---|---|
| Type | Int32 |
| Required | False |
| Default | 0 |

## OUTPUTS

**SSHCommandResult** — contains `Output` (stdout), `Error` (stderr), `ExitCode`, `SessionId`, and `ComputerName`.

## RELATED LINKS

- [New-SSHSession](New-SSHSession.md)
- [Enter-SSHSession](Enter-SSHSession.md)
