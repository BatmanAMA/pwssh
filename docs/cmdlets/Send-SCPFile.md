# Send-SCPFile

## SYNOPSIS

Uploads a file to a remote host via SCP.

## SYNTAX

```
Send-SCPFile [-SessionId] <Int32> [-LocalPath] <String> [-RemotePath] <String>
    [-Recurse] [<CommonParameters>]

Send-SCPFile -Session <SSHSessionInfo> [-LocalPath] <String> [-RemotePath] <String>
    [-Recurse] [<CommonParameters>]
```

## DESCRIPTION

Copies a local file to the remote host using the SCP protocol over an existing SSH session.

## EXAMPLES

### Example 1: Upload a file

```powershell
Send-SCPFile -SessionId 1 -LocalPath ./app.tar.gz -RemotePath /tmp/app.tar.gz
```

### Example 2: Upload a directory recursively

```powershell
Send-SCPFile -SessionId 1 -LocalPath ./deploy/ -RemotePath /opt/app/ -Recurse
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

### -LocalPath

Path to the local file or directory to upload.

| | |
|---|---|
| Type | String |
| Position | 0 |
| Required | True |
| Aliases | Source, Path |

### -RemotePath

Destination path on the remote host.

| | |
|---|---|
| Type | String |
| Position | 1 |
| Required | True |
| Aliases | Destination |

### -Recurse

Recursively upload directories.

| | |
|---|---|
| Type | SwitchParameter |
| Required | False |

## RELATED LINKS

- [Receive-SCPFile](Receive-SCPFile.md)
- [Send-SFTPFile](Send-SFTPFile.md)
