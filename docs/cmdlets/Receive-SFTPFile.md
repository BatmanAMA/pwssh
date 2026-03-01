# Receive-SFTPFile

## SYNOPSIS

Downloads a file from a remote host via SFTP.

## SYNTAX

```
Receive-SFTPFile [-SessionId] <Int32> [-RemotePath] <String> [-LocalPath] <String>
    [-Overwrite] [<CommonParameters>]

Receive-SFTPFile -Session <SSHSessionInfo> [-RemotePath] <String> [-LocalPath] <String>
    [-Overwrite] [<CommonParameters>]
```

## DESCRIPTION

Copies a remote file to the local machine using SFTP.

## EXAMPLES

### Example 1: Download a log file

```powershell
Receive-SFTPFile -SessionId 1 -RemotePath /var/log/app.log -LocalPath ./app.log
```

### Example 2: Download with overwrite

```powershell
Receive-SFTPFile -SessionId 1 -RemotePath /backups/db.sql -LocalPath ./db.sql -Overwrite
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

### -Overwrite

Overwrite the local file if it exists.

| | |
|---|---|
| Type | SwitchParameter |
| Required | False |

## RELATED LINKS

- [Send-SFTPFile](Send-SFTPFile.md)
- [Receive-SCPFile](Receive-SCPFile.md)
- [Get-SFTPChildItem](Get-SFTPChildItem.md)
