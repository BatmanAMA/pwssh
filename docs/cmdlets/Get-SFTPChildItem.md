# Get-SFTPChildItem

## SYNOPSIS

Lists files and directories on a remote host via SFTP.

## SYNTAX

```
Get-SFTPChildItem [-SessionId] <Int32> [[-Path] <String>] [-Recurse] [<CommonParameters>]

Get-SFTPChildItem -Session <SSHSessionInfo> [[-Path] <String>] [-Recurse] [<CommonParameters>]
```

## DESCRIPTION

Returns a listing of remote directory contents using SFTP, similar to `Get-ChildItem`.

## EXAMPLES

### Example 1: List a directory

```powershell
Get-SFTPChildItem -SessionId 1 -Path /var/log
```

### Example 2: Recursive listing

```powershell
Get-SFTPChildItem -SessionId 1 -Path /etc -Recurse
```

### Example 3: List home directory (default)

```powershell
Get-SFTPChildItem -SessionId 1
```

## PARAMETERS

### -SessionId

The session ID to use.

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

### -Path

The remote directory path to list. Defaults to the user's home directory.

| | |
|---|---|
| Type | String |
| Position | 0 |
| Required | False |
| Default | . |

### -Recurse

Recursively list subdirectories.

| | |
|---|---|
| Type | SwitchParameter |
| Required | False |

## RELATED LINKS

- [Send-SFTPFile](Send-SFTPFile.md)
- [Receive-SFTPFile](Receive-SFTPFile.md)
