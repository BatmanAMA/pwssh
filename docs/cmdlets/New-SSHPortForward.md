# New-SSHPortForward

## SYNOPSIS

Creates an SSH port forward (tunnel).

## SYNTAX

```
New-SSHPortForward [-SessionId] <Int32> -Type <String> -BoundPort <Int32>
    [-BoundHost <String>] [-RemoteHost <String>] [-RemotePort <Int32>] [<CommonParameters>]

New-SSHPortForward -Session <SSHSessionInfo> -Type <String> -BoundPort <Int32>
    [-BoundHost <String>] [-RemoteHost <String>] [-RemotePort <Int32>] [<CommonParameters>]
```

## DESCRIPTION

Sets up local, remote, or dynamic (SOCKS) port forwarding through an SSH session.

## EXAMPLES

### Example 1: Local port forward to a database

```powershell
New-SSHPortForward -SessionId 1 -Type Local -BoundPort 8080 -RemoteHost db.internal -RemotePort 5432
```

### Example 2: Dynamic SOCKS proxy

```powershell
New-SSHPortForward -SessionId 1 -Type Dynamic -BoundPort 1080
```

### Example 3: Remote port forward

```powershell
New-SSHPortForward -SessionId 1 -Type Remote -BoundPort 9090 -RemoteHost localhost -RemotePort 80
```

## PARAMETERS

### -SessionId

The session ID to use for the tunnel.

| | |
|---|---|
| Type | Int32 |
| Required | True |

### -Session

An SSHSessionInfo object.

| | |
|---|---|
| Type | SSHSessionInfo |
| Required | True |
| Pipeline Input | True (ByValue) |

### -Type

The type of port forward: `Local`, `Remote`, or `Dynamic`.

| | |
|---|---|
| Type | String |
| Required | True |
| Valid Values | Local, Remote, Dynamic |

### -BoundHost

The local address to bind. Defaults to `localhost`.

| | |
|---|---|
| Type | String |
| Required | False |
| Default | localhost |

### -BoundPort

The local port to bind.

| | |
|---|---|
| Type | Int32 |
| Required | True |

### -RemoteHost

The remote destination host (for Local and Remote forwarding). Defaults to `localhost`.

| | |
|---|---|
| Type | String |
| Required | False |
| Default | localhost |

### -RemotePort

The remote destination port.

| | |
|---|---|
| Type | Int32 |
| Required | False |

## OUTPUTS

**SSHPortForward**

## RELATED LINKS

- [Get-SSHPortForward](Get-SSHPortForward.md)
- [Remove-SSHPortForward](Remove-SSHPortForward.md)
