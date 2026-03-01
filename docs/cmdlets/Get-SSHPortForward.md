# Get-SSHPortForward

## SYNOPSIS

Lists active SSH port forwards.

## SYNTAX

```
Get-SSHPortForward [[-ForwardId] <Int32[]>] [-SessionId <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Returns SSHPortForward objects for active tunnels.

## EXAMPLES

### Example 1: List all forwards

```powershell
Get-SSHPortForward
```

### Example 2: Filter by session

```powershell
Get-SSHPortForward -SessionId 1
```

## PARAMETERS

### -ForwardId

One or more forward IDs to retrieve.

| | |
|---|---|
| Type | Int32[] |
| Position | 0 |
| Required | False |

### -SessionId

Filter by session ID.

| | |
|---|---|
| Type | Int32 |
| Required | False |

## OUTPUTS

**SSHPortForward**

## RELATED LINKS

- [New-SSHPortForward](New-SSHPortForward.md)
- [Remove-SSHPortForward](Remove-SSHPortForward.md)
