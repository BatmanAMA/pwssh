# Security

pwssh applies several hardening measures on top of SSH.NET defaults.

## Host Key Verification

pwssh uses Trust On First Use (TOFU), the same model as OpenSSH:

| Scenario | Behavior |
|---|---|
| Unknown host | Prompts to accept (or use `-AcceptKey` to auto-accept) |
| Known host, matching key | Trusted automatically |
| Known host, **changed** key | **Connection refused** — possible MITM attack |

Control this with `-StrictHostKeyChecking`:

- `Ask` (default) — prompt for unknown hosts, reject changed keys
- `Yes` — reject both unknown and changed keys
- `No` — accept all keys (same as `-AcceptKey`)

Known hosts are persisted to `~/.ssh/known_hosts` in OpenSSH format.

## Algorithm Hardening

The following weak algorithms are stripped from SSH.NET's default negotiation set before every connection:

**Ciphers removed:** `3des-cbc`, `blowfish-cbc`, `arcfour`, `arcfour128`, `arcfour256`, `cast128-cbc`

**MACs removed:** `hmac-md5`, `hmac-md5-96`, `hmac-sha1-96`

**Key exchange removed:** `diffie-hellman-group1-sha1`

This prevents downgrade attacks where a compromised server forces negotiation to a weak algorithm.

## Assembly Integrity

On module load, pwssh verifies the SHA-256 hash of `Renci.SshNet.dll` against a stored hash file
(`Renci.SshNet.dll.sha256`) generated at build time. If the hash does not match, the module refuses
to load. This prevents supply-chain attacks where the DLL is replaced after build.

## Memory Safety

### What we do

**C# layer (`SSHCrypto.cs`):**

- `SecureBuffer` class — pins `byte[]` via `GCHandle.Alloc(Pinned)` so the GC cannot relocate copies, then zeroes and unpins on `Dispose()`
- `CryptoUtil.Wipe()` — zeroes any `byte[]` containing key or credential material
- All crypto paths (key generation, encryption, decryption, KDF) wipe intermediate buffers in `finally` blocks:
  SHA-512 hashes, clamped scalars, derived keys, AES key/IV, passphrase bytes, Ed25519 seed copies

**PowerShell layer:**

- BSTR pointers from `SecureString` conversion are zeroed via `ZeroFreeBSTR`
- Plaintext string variables (`$passStr`, `$plain`, `$privContent`) are set to `$null` in `finally` blocks to remove managed references
- `NetworkCredential` references are set to `$null` immediately after use

### Known limitations

These are fundamental .NET limitations, not bugs:

- **`string` is immutable** — once a password or passphrase is converted to `System.String`, it cannot be zeroed on the managed heap. Setting the variable to `$null` removes the reference but the bytes persist until the GC collects and the memory is reused.
- **SSH.NET takes `string` parameters** — `PasswordAuthenticationMethod` and `PrivateKeyFile` constructors accept `string` for passwords and passphrases. The plaintext lives inside SSH.NET objects for the lifetime of the connection. This is only fixable upstream.
- **`BigInteger` is immutable** — Ed25519 scalar arithmetic uses `System.Numerics.BigInteger`, which allocates new objects per operation. Secret scalars cannot be wiped from intermediate `BigInteger` instances.
- **Ed25519 timing** — on .NET runtimes prior to .NET 9, the `BigInteger`-based Ed25519 implementation uses non-constant-time arithmetic. A warning is emitted at key generation time. For production keys on shared infrastructure, use `ssh-keygen` or upgrade to .NET 9+ (PowerShell 7.5+).

## Key File Permissions

`New-SSHKeyPair` sets restrictive permissions on generated private keys:

- **Linux/macOS:** `chmod 600` (owner read/write only)
- **Windows:** ACL restricted to the current user via `Set-Acl`

## Reporting Vulnerabilities

If you discover a security vulnerability, please open an issue at
[github.com/BatmanAMA/pwssh/issues](https://github.com/BatmanAMA/pwssh/issues)
or contact the maintainer directly.
