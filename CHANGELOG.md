# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - Unreleased

Version 0.1.0 could not be imported, could not connect, and wrote key files that
OpenSSH rejected. This version makes the module work end to end and closes the
security gaps found in review.

### Changed behaviour

These changes can affect existing scripts.

- Errors reported by the commands are non-terminating unless `-ErrorAction Stop`
  is passed. The module previously forced every error to be terminating.
- `SSHPortForward.ToString()` for a remote forward now prints the listener
  first, then the destination, matching local forwards.
- `New-SSHSession -AcceptKey` now accepts only hosts that are not yet in
  `known_hosts`. A host whose key has changed is refused.
- `New-SSHSession -StrictHostKeyChecking` has a new value, `AcceptNew`, which
  records and trusts unknown hosts and refuses changed keys. `-AcceptKey` turns
  the default `Ask` into `AcceptNew`.
- `-StrictHostKeyChecking No` refuses a changed host key when a password would
  be sent (`-Credential`). With key authentication the changed key is still
  accepted, with a warning.
- A key other than the ones recorded for a known host is always treated as
  changed.
- `Add-SSHKnownHost` validates the host name, key type and key data, and does
  not add an entry that is already present.
- `New-SSHKeyPair` rejects RSA keys below 2048 bits. RSA sizes must be a
  multiple of 8 between 2048 and 16384 bits.
- Relative local paths are resolved against the current PowerShell location,
  not against the working directory of the process.
- The output types (`SSHSessionInfo`, `SSHCommandResult`, `SSHPortForward`,
  `SSHHostKey`, `SSHKnownHost`) are now compiled C# types and no longer
  PowerShell classes. The type names are unchanged.
- The downloaded assemblies are now placed in `lib/core` (PowerShell 7) and
  `lib/desktop` (Windows PowerShell 5.1).
- `Invoke-SSHCommand` reports `ExitCode` `-1` when the server sent no exit
  status. Previously this looked like success.
- `Invoke-SSHCommand` no longer writes the command text to the verbose stream.
- In `Enter-SSHSession`, Ctrl+C is sent to the remote program. It no longer
  returns to the local shell; type `exit`, or press Enter and then `~.`.

### Added

- OpenSSH `known_hosts` semantics for host key verification: hashed host names,
  wildcard and negated patterns, per-host ports, `@revoked` lines, trailing
  comments, several keys per host, and the system-wide files.
- `New-SSHSession -KnownHostsPath` to use a specific `known_hosts` file.
- `New-SSHSession` reads `HostName`, `User`, `Port` and `IdentityFile` from
  `~/.ssh/config`. `-ConfigFile` selects another file or, with `none`, turns
  this off.
- Passwords are also offered through keyboard-interactive authentication.
- All default keys (`id_ed25519`, `id_ecdsa`, `id_rsa`) that can be loaded are
  offered, after any `IdentityFile` entries from the ssh config file.
- `Enter-SSHSession` follows changes of the local window size, ends when the
  remote shell exits, and supports the `~.` escape sequence.
- `Add-SSHKnownHost -HashHostName` stores the host name hashed.
- `Get-SSHKnownHost -Port` filters by port.
- BouncyCastle and the .NET Framework dependencies of SSH.NET are downloaded by
  `build.ps1`. Every package is pinned by version and SHA-256.
- Unit tests for host key decisions, `known_hosts` parsing, ssh config parsing
  and OpenSSH interoperability (reference bcrypt_pbkdf vectors and `ssh-keygen`
  round trips).
- Integration tests that start a private `sshd` and drive the built module.
- `README.md` and this changelog.

### Changed

- Host key verification runs in compiled code. SSH.NET raises its
  `HostKeyReceived` event on a thread without a runspace, so the previous script
  block handler could never run.
- In `Ask` mode the prompt is shown on the pipeline thread, and the connection
  is made again after the key has been accepted.
- `Receive-SFTPFile` downloads to a temporary `.part` file and renames it when
  the transfer has completed.
- `Remove-SSHKnownHost` replaces the `known_hosts` file atomically.
- CI imports the built module on every edition, runs the integration suite, no
  longer uses a third-party action, and runs with a read-only token.
- Comment-based help revised for all exported commands.

### Fixed

- The module could not be imported: the dot-sourced PowerShell classes were not
  visible to the public functions, and `SSHPortForward` had a parse error.
- Windows PowerShell 5.1 could not load the module because of three-argument
  `Join-Path` calls and `BigInteger.GetBitLength`. Both have been removed.
- mpint encoding. RSA keys and about half of all ECDSA keys were written in a
  form that OpenSSH rejected.
- bcrypt_pbkdf (Blowfish final round, output byte order, interleaving of output
  blocks). Passphrase-protected keys now interoperate with OpenSSH in both
  directions.

### Security

- SFTP and SCP connections are pinned to the host key the session accepted.
  Previously they connected without any host key verification.
- Private key files are created with owner-only permissions before the key is
  written to them.
- Key files are validated while they are parsed, and the number of KDF rounds
  accepted from a key file is bounded.

## [0.1.0]

Initial implementation.

- SSH sessions and remote command execution on top of SSH.NET.
- Interactive shell.
- SCP and SFTP file transfer.
- Local, remote and dynamic port forwarding.
- Key generation and inspection (`New-SSHKeyPair`, `ConvertTo-SSHPublicKey`,
  `Get-SSHKeyFingerprint`, `Test-SSHKeyFile`).
- `known_hosts` commands (`Get-SSHHostKey`, `Get-SSHKnownHost`,
  `Add-SSHKnownHost`, `Remove-SSHKnownHost`).
