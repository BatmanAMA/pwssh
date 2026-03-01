# Test-SSHKeyFile

## SYNOPSIS

Validates an SSH key file.

## SYNTAX

```
Test-SSHKeyFile [-Path] <String> [-Passphrase <SecureString>] [<CommonParameters>]
```

## DESCRIPTION

Tests whether a file is a valid OpenSSH key (public or private). Returns a validation result object. Equivalent to `ssh-keygen -y` for validation.

## EXAMPLES

### Example 1: Validate a key

```powershell
Test-SSHKeyFile -Path ~/.ssh/id_ed25519
```

### Example 2: Validate all keys in ~/.ssh

```powershell
Get-ChildItem ~/.ssh/id_* | Test-SSHKeyFile
```

## PARAMETERS

### -Path

Path to the key file to validate.

| | |
|---|---|
| Type | String |
| Position | 0 |
| Required | True |
| Pipeline Input | True (ByValue, ByPropertyName) |
| Aliases | FullName |

### -Passphrase

SecureString passphrase if the private key is encrypted.

| | |
|---|---|
| Type | SecureString |
| Required | False |

## OUTPUTS

**SSHKeyValidationResult** — contains `Path`, `Valid`, `KeyType`, `Format`, `Encrypted`, and `Error`.

## RELATED LINKS

- [New-SSHKeyPair](New-SSHKeyPair.md)
- [Get-SSHKeyFingerprint](Get-SSHKeyFingerprint.md)
