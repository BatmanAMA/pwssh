# Remove-SSHPortForward

## SYNOPSIS

Stops and removes SSH port forwards.

## SYNTAX

```
Remove-SSHPortForward [-ForwardId] <Int32[]> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-SSHPortForward -Forward <SSHPortForward[]> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION

Stops the forwarded port and removes it from the store.

## EXAMPLES

### Example 1: Remove by ID

```powershell
Remove-SSHPortForward -ForwardId 1
```

### Example 2: Remove all forwards for a session

```powershell
Get-SSHPortForward -SessionId 1 | Remove-SSHPortForward
```

## PARAMETERS

### -ForwardId

One or more forward IDs to remove.

| | |
|---|---|
| Type | Int32[] |
| Position | 0 |
| Required | True |
| Pipeline Input | True (ByPropertyName) |

### -Forward

One or more SSHPortForward objects to remove.

| | |
|---|---|
| Type | SSHPortForward[] |
| Required | True |
| Pipeline Input | True (ByValue) |

## RELATED LINKS

- [New-SSHPortForward](New-SSHPortForward.md)
- [Get-SSHPortForward](Get-SSHPortForward.md)
