# Send-SFTPFile

## SYNOPSIS

Uploads a file to a remote host via SFTP.

## SYNTAX

```
Send-SFTPFile [-SessionId] <Int32> [-LocalPath] <String> [-RemotePath] <String>
    [-Overwrite] [<CommonParameters>]

Send-SFTPFile -Session <SSHSessionInfo> [-LocalPath] <String> [-RemotePath] <String>
    [-Overwrite] [<CommonParameters>]
```

## DESCRIPTION

Copies a local file to the remote host using SFTP, which provides better error handling and progress tracking than SCP.

## EXAMPLES

### Example 1: Upload a configuration file

```powershell
Send-SFTPFile -SessionId 1 -LocalPath ./config.yml -RemotePath /etc/myapp/config.yml
```

### Example 2: Upload with overwrite

```powershell
Send-SFTPFile -SessionId 1 -LocalPath ./app.jar -RemotePath /opt/app/app.jar -Overwrite
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

Path to the local file to upload.

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

### -Overwrite

Overwrite the remote file if it exists.

| | |
|---|---|
| Type | SwitchParameter |
| Required | False |

## RELATED LINKS

- [Receive-SFTPFile](Receive-SFTPFile.md)
- [Send-SCPFile](Send-SCPFile.md)
- [Get-SFTPChildItem](Get-SFTPChildItem.md)
