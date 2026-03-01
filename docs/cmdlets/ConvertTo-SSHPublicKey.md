# ConvertTo-SSHPublicKey

## SYNOPSIS

Extracts the public key from an OpenSSH private key file.

## SYNTAX

```
ConvertTo-SSHPublicKey [-Path] <String> [-Passphrase <SecureString>] [<CommonParameters>]
```

## DESCRIPTION

Reads an OpenSSH private key file and outputs the corresponding public key line (suitable for `authorized_keys`). Equivalent to `ssh-keygen -y`.

## EXAMPLES

### Example 1: Extract public key

```powershell
ConvertTo-SSHPublicKey -Path ~/.ssh/id_ed25519
```

### Example 2: Extract from encrypted key

```powershell
$pass = Read-Host -AsSecureString
ConvertTo-SSHPublicKey -Path ~/.ssh/id_rsa -Passphrase $pass
```

## PARAMETERS

### -Path

Path to the private key file.

| | |
|---|---|
| Type | String |
| Position | 0 |
| Required | True |
| Pipeline Input | True (ByValue, ByPropertyName) |
| Aliases | PrivateKeyPath, FullName |

### -Passphrase

SecureString passphrase if the key is encrypted.

| | |
|---|---|
| Type | SecureString |
| Required | False |

## OUTPUTS

**SSHPublicKeyInfo** — contains `KeyType`, `PublicKeyLine`, `Comment`, `Fingerprint`, and `SourceFile`.

## RELATED LINKS

- [New-SSHKeyPair](New-SSHKeyPair.md)
- [Get-SSHKeyFingerprint](Get-SSHKeyFingerprint.md)
