# Get-SSHKeyFingerprint

## SYNOPSIS

Shows the fingerprint of an SSH key file.

## SYNTAX

```
Get-SSHKeyFingerprint [-Path] <String> [-Algorithm <String>] [-Passphrase <SecureString>]
    [<CommonParameters>]
```

## DESCRIPTION

Reads an SSH public or private key file and displays its fingerprint. Equivalent to `ssh-keygen -l`.

## EXAMPLES

### Example 1: Get fingerprint of a public key

```powershell
Get-SSHKeyFingerprint -Path ~/.ssh/id_ed25519.pub
```

### Example 2: Get MD5 fingerprint

```powershell
Get-SSHKeyFingerprint -Path ~/.ssh/id_rsa -Algorithm MD5
```

## PARAMETERS

### -Path

Path to a public key (`.pub`) or private key file.

| | |
|---|---|
| Type | String |
| Position | 0 |
| Required | True |
| Pipeline Input | True (ByValue, ByPropertyName) |
| Aliases | FullName |

### -Algorithm

Hash algorithm for the fingerprint: `SHA256` or `MD5`. Defaults to `SHA256`.

| | |
|---|---|
| Type | String |
| Required | False |
| Default | SHA256 |

### -Passphrase

SecureString passphrase if the private key is encrypted.

| | |
|---|---|
| Type | SecureString |
| Required | False |

## RELATED LINKS

- [New-SSHKeyPair](New-SSHKeyPair.md)
- [ConvertTo-SSHPublicKey](ConvertTo-SSHPublicKey.md)
- [Test-SSHKeyFile](Test-SSHKeyFile.md)
