# Receive-SCPFile

## SYNOPSIS

Downloads a file from a remote host via SCP.

## SYNTAX

```
Receive-SCPFile [-SessionId] <Int32> [-RemotePath] <String> [-LocalPath] <String>
    [-Recurse] [<CommonParameters>]

Receive-SCPFile -Session <SSHSessionInfo> [-RemotePath] <String> [-LocalPath] <String>
    [-Recurse] [<CommonParameters>]
```

## DESCRIPTION

Copies a remote file to the local machine using SCP over an existing SSH session.

## EXAMPLES

### Example 1: Download a file

```powershell
Receive-SCPFile -SessionId 1 -RemotePath /var/log/syslog -LocalPath ./syslog.txt
```

### Example 2: Download a directory recursively

```powershell
Receive-SCPFile -SessionId 1 -RemotePath /etc/nginx/ -LocalPath ./nginx-conf/ -Recurse
```

## PARAMETERS

### -SessionId

The session ID to use for the transfer.

| | |
|---|---|
| Type | Int32 |
| Required | True |

### -Session

An SSHSessionInfo object to use for the transfer.

| | |
|---|---|
| Type | SSHSessionInfo |
| Required | True |
| Pipeline Input | True (ByValue) |

### -RemotePath

Path on the remote host to download.

| | |
|---|---|
| Type | String |
| Position | 0 |
| Required | True |
| Aliases | Source |

### -LocalPath

Local destination path.

| | |
|---|---|
| Type | String |
| Position | 1 |
| Required | True |
| Aliases | Destination, Path |

### -Recurse

Recursively download directories.

| | |
|---|---|
| Type | SwitchParameter |
| Required | False |

## RELATED LINKS

- [Send-SCPFile](Send-SCPFile.md)
- [Receive-SFTPFile](Receive-SFTPFile.md)
