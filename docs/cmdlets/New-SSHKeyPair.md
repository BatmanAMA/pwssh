# New-SSHKeyPair

## SYNOPSIS

Generates a new SSH key pair using pure .NET cryptography.

## SYNTAX

```
New-SSHKeyPair [[-Path] <String>] [-KeyType <String>] [-KeySize <Int32>]
    [-Comment <String>] [-Passphrase <SecureString>] [-Force] [-WhatIf] [-Confirm]
    [<CommonParameters>]
```

## DESCRIPTION

Creates a new SSH private/public key pair in OpenSSH format. Supports Ed25519, RSA, and ECDSA key types. No external tools (`ssh-keygen`) required.

On .NET runtimes prior to .NET 9, Ed25519 key generation uses non-constant-time `BigInteger` arithmetic. A warning is emitted in this case. For production keys on shared infrastructure, use `ssh-keygen` or upgrade to .NET 9+ (PowerShell 7.5+).

## EXAMPLES

### Example 1: Generate an Ed25519 key (default)

```powershell
New-SSHKeyPair -Path ~/.ssh/id_ed25519
```

### Example 2: Generate a 4096-bit RSA key with a comment

```powershell
New-SSHKeyPair -Path ~/.ssh/id_rsa -KeyType RSA -KeySize 4096 -Comment 'deploy key'
```

### Example 3: Generate a passphrase-protected key

```powershell
$pass = Read-Host -AsSecureString -Prompt 'Passphrase'
New-SSHKeyPair -Path ~/.ssh/id_ed25519 -Passphrase $pass
```

## PARAMETERS

### -Path

Output path for the private key. The public key will be written to `Path.pub`. Defaults to `~/.ssh/id_<type>`.

| | |
|---|---|
| Type | String |
| Position | 0 |
| Required | False |

### -KeyType

The key algorithm: `Ed25519`, `RSA`, or `ECDSA`. Defaults to `Ed25519`.

| | |
|---|---|
| Type | String |
| Required | False |
| Default | Ed25519 |
| Valid Values | Ed25519, RSA, ECDSA |

### -KeySize

Key size in bits. For RSA: 2048, 3072, 4096. For ECDSA: 256, 384, 521. Ignored for Ed25519.

| | |
|---|---|
| Type | Int32 |
| Required | False |

### -Comment

Comment to embed in the public key. Defaults to `user@hostname`.

| | |
|---|---|
| Type | String |
| Required | False |

### -Passphrase

SecureString passphrase to protect the private key. Uses bcrypt-pbkdf with AES-256-CTR encryption.

| | |
|---|---|
| Type | SecureString |
| Required | False |

### -Force

Overwrite existing key files.

| | |
|---|---|
| Type | SwitchParameter |
| Required | False |

## OUTPUTS

**SSHKeyPairInfo** — contains `PrivateKeyPath`, `PublicKeyPath`, `KeyType`, `Fingerprint`, `Comment`, and `Encrypted`.

## RELATED LINKS

- [ConvertTo-SSHPublicKey](ConvertTo-SSHPublicKey.md)
- [Get-SSHKeyFingerprint](Get-SSHKeyFingerprint.md)
- [Test-SSHKeyFile](Test-SSHKeyFile.md)
