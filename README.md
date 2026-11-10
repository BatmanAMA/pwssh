# pwssh

pwssh is an SSH client module for PowerShell. It is built on the
[SSH.NET](https://github.com/sshnet/SSH.NET) library and adds the parts of an
OpenSSH client that SSH.NET leaves to the caller: host key verification against
`known_hosts`, reading `~/.ssh/config`, and key management that is compatible
with `ssh-keygen`.

It provides:

- persistent SSH sessions and remote command execution
- an interactive remote shell
- file transfer with SCP and SFTP
- local, remote and dynamic (SOCKS) port forwarding
- generation and inspection of OpenSSH key files, without `ssh-keygen`
- management of `known_hosts` entries

## Status

Version 0.2.0 has not been released yet.

Tested on: PowerShell 7.4 on Linux against OpenSSH 9.6. On that platform the
unit suite passes, the integration suite passes against a local `sshd`, and
key files have been exchanged with `ssh-keygen` in both directions (keys written
by pwssh are read by `ssh-keygen`, and keys written by `ssh-keygen` are read by
pwssh).

Not yet run: Windows PowerShell 5.1, PowerShell 7 on Windows and PowerShell 7 on
macOS. The code paths for these platforms are written, and the CI workflow is
set up to cover them, but they have not been executed so far. Treat them as
untested.

Not covered by the automated tests: the interactive shell (`Enter-SSHSession`),
remote and dynamic port forwards, and, in the self-hosted integration run,
password and keyboard-interactive authentication.

## Requirements

- Windows PowerShell 5.1, or PowerShell 7.2 or later. The module refuses to
  load on PowerShell 6.x, 7.0 and 7.1.
- SSH.NET 2024.2.0 and its dependencies. They are not stored in the repository.
  `build.ps1` downloads them from nuget.org. Every package is pinned to an exact
  version and to the SHA-256 hash of its `.nupkg`, and a download whose hash
  differs is rejected. The packages are:
  - both editions: SSH.NET 2024.2.0, BouncyCastle.Cryptography 2.4.0
  - Windows PowerShell 5.1 only: Microsoft.Bcl.AsyncInterfaces 1.0.0,
    System.Formats.Asn1 8.0.1, System.Threading.Tasks.Extensions 4.5.2,
    System.Runtime.CompilerServices.Unsafe 4.5.3, System.Buffers 4.5.1,
    System.Memory 4.5.5, System.Numerics.Vectors 4.5.0, System.ValueTuple 4.5.0
- Pester 5 to run the tests. `build.ps1` installs it for the current user if it
  is missing.

The module also contains C# source (`src/pwssh/Private/CSharp`) that is compiled
with `Add-Type` when the module is imported. No separate compiler is needed.

## Build and install from source

```powershell
git clone https://github.com/BatmanAMA/pwssh.git
cd pwssh
./build.ps1
Import-Module ./output/pwssh/pwssh.psd1
```

`./build.ps1` downloads the dependencies into `src/pwssh/lib/core` (PowerShell
7) and `src/pwssh/lib/desktop` (Windows PowerShell 5.1) if they are not there
yet, and stages the module in `./output/pwssh`. To install it, copy the
`output/pwssh` directory into one of the directories listed in
`$env:PSModulePath`.

Build tasks:

| Command | What it does |
| --- | --- |
| `./build.ps1` or `./build.ps1 -Task Build` | Download dependencies if missing and stage the module in `./output/pwssh` |
| `./build.ps1 -Task Test` | Build, then run the unit tests |
| `./build.ps1 -Task Integration` | Build, then run the integration tests |
| `./build.ps1 -Task Clean` | Remove `./output`, `./TestResults` and the downloaded dependencies |

If the module is imported without the dependencies, it prints a warning. The
key and `known_hosts` commands still work; commands that connect to a server do
not.

## Quick start

```powershell
Import-Module ./output/pwssh/pwssh.psd1

# Connect. On first contact you are shown the host key fingerprint and asked
# whether to trust it.
$session = New-SSHSession -ComputerName admin@server01 -KeyFile ~/.ssh/id_ed25519

# Run a command
$result = Invoke-SSHCommand -Session $session -Command 'uname -a'
$result.Output
$result.ExitCode

# Transfer files
Send-SFTPFile    -Session $session -LocalPath ./app.conf -RemotePath /tmp/app.conf
Receive-SFTPFile -Session $session -RemotePath /var/log/app.log -LocalPath ./app.log
Get-SFTPChildItem -Session $session -Path /var/log

# Forward local port 8080 to a host that only the server can reach
New-SSHPortForward -Session $session -Type Local -BoundPort 8080 -RemoteHost db.internal -RemotePort 5432

# Interactive shell. The SSH session stays open after you leave the shell.
Enter-SSHSession -Session $session

# Close the session, its port forwards and its SFTP and SCP connections
Remove-SSHSession -Session $session
```

Every command has help with examples: `Get-Help New-SSHSession -Full`.

## Command reference

| Area | Command | Purpose |
| --- | --- | --- |
| Sessions | `New-SSHSession` | Connect to a host, verify its host key, authenticate and return a session |
| | `Get-SSHSession` | List sessions, optionally by ID, by host name or only connected ones |
| | `Remove-SSHSession` | Close sessions together with their port forwards and transfer connections |
| | `Enter-SSHSession` | Open an interactive shell on a session |
| Commands | `Invoke-SSHCommand` | Run a command on one or more sessions and return output, error text and exit code |
| SCP | `Send-SCPFile` | Upload a file, or a directory with `-Recurse` |
| | `Receive-SCPFile` | Download a file, or a directory with `-Recurse` |
| SFTP | `Send-SFTPFile` | Upload a file; refuses to replace a remote file without `-Overwrite` |
| | `Receive-SFTPFile` | Download a file through a temporary `.part` file; refuses to replace a local file without `-Overwrite` |
| | `Get-SFTPChildItem` | List a remote directory, optionally recursively |
| Port forwarding | `New-SSHPortForward` | Start a local, remote or dynamic (SOCKS) forward |
| | `Get-SSHPortForward` | List forwards |
| | `Remove-SSHPortForward` | Stop and remove forwards |
| Keys | `New-SSHKeyPair` | Generate an Ed25519, RSA or ECDSA key pair in OpenSSH format |
| | `ConvertTo-SSHPublicKey` | Derive the public key line from an OpenSSH private key |
| | `Get-SSHKeyFingerprint` | Show the SHA256 or MD5 fingerprint of a key file |
| | `Test-SSHKeyFile` | Check whether a file is a valid OpenSSH key |
| Host keys | `Get-SSHHostKey` | Fetch the host key a server presents, without verifying it |
| | `Get-SSHKnownHost` | List entries of a `known_hosts` file |
| | `Add-SSHKnownHost` | Add a host key to `known_hosts` |
| | `Remove-SSHKnownHost` | Remove a host's entries from `known_hosts` |

Notes that apply to several commands:

- **Local paths.** Local paths may be relative to the current PowerShell
  location and may start with `~`.
- **File transfers use their own connection.** SSH.NET's SFTP and SCP clients
  cannot share the session's connection. The first SFTP command and the first
  SCP command on a session each open one further connection, which is reused
  afterwards and closed with the session. These connections are pinned to the
  host key the session accepted when it was established: if the server presents
  any other key, the transfer is refused.
- **Exit codes.** `Invoke-SSHCommand` does not treat a non-zero exit code as an
  error. `ExitCode` is `-1` when the server reported no exit status, for example
  when the command was killed by a signal. The command text is never written to
  the verbose stream.
- **Errors.** Commands report failures as non-terminating errors, as built-in
  cmdlets do. Pass `-ErrorAction Stop` to catch them with `try`/`catch`.

## Host key verification

`New-SSHSession` checks the server's host key before any credential is sent.
The check runs for every connection and cannot be skipped.

### Which files are consulted

By default, in this order:

1. `~/.ssh/known_hosts`
2. `~/.ssh/known_hosts2`
3. `/etc/ssh/ssh_known_hosts`
4. `/etc/ssh/ssh_known_hosts2`

On Windows the system-wide files are `%ProgramData%\ssh\ssh_known_hosts` and
`%ProgramData%\ssh\ssh_known_hosts2`. Files that do not exist or cannot be read
are skipped. New keys are always recorded in `~/.ssh/known_hosts`, as a plain
(not hashed) entry.

With `-KnownHostsPath <file>`, only that file is consulted, and new keys are
recorded in it. The user and system-wide files are ignored.

The host is looked up under the name that is actually connected to (after
`HostName` from the ssh config file has been applied), as `host` for port 22 and
as `[host]:port` for any other port.

### How a key is classified

- **Revoked**: the key appears on an `@revoked` line whose pattern matches the
  host. The connection is refused in every mode.
- **Known**: a line for the host carries exactly this key. The connection is
  trusted in every mode. A key recorded for the bare host name is also accepted
  when connecting to a non-default port, provided nothing is recorded for
  `[host]:port` itself.
- **Changed**: there are lines for the host, but none carries this key. This
  includes the case where the server presents a key of a different type than
  the recorded one.
- **Unknown**: there is no line for the host.

`@cert-authority` lines are ignored.

### `-StrictHostKeyChecking`

| Mode | Unknown host | Changed key |
| --- | --- | --- |
| `Ask` (default) | Shows the key type and SHA256 fingerprint and asks. Only the answer `yes` is accepted; the key is then recorded and the connection is made again. If the session cannot prompt, the connection is refused. | Refused |
| `Yes` | Refused. Nothing is written to `known_hosts`. | Refused |
| `AcceptNew` | Recorded and trusted without asking | Refused |
| `No` | Recorded and trusted without asking | Accepted with a warning if only key authentication is used. Refused if a password would be sent, that is when `-Credential` is given. |

In `No` mode a changed key does not replace the recorded one. The warning is
shown on every connection until the stale entry is removed with
`Remove-SSHKnownHost`.

In `Ask` mode the first connection attempt is aborted before authentication, the
question is asked, and a second connection is opened. The second connection
succeeds only if the server presents the key that was just recorded.

### `-AcceptKey`

`-AcceptKey` changes the default mode `Ask` into `AcceptNew`: the key of a host
that is not yet known is recorded and trusted without a prompt. It never
accepts a changed key. It has no effect when `-StrictHostKeyChecking` is given
explicitly as `Yes`, `No` or `AcceptNew`.

### Managing known_hosts

```powershell
# Fetch the key a server presents. It is NOT verified at this point.
$key = Get-SSHHostKey -ComputerName server01
$key.Fingerprint

# Record it only after comparing the fingerprint with one obtained through a
# trusted channel
if ($key.Fingerprint -eq 'SHA256:<fingerprint from a trusted source>') {
    $key | Add-SSHKnownHost
}

Get-SSHKnownHost -HostName server01
Remove-SSHKnownHost -HostName server01
```

`Get-SSHHostKey` returns whatever answered at the address. Adding its output to
`known_hosts` without comparing the fingerprint gives no protection against a
man-in-the-middle.

`Add-SSHKnownHost` validates its input, does not add an entry that is already
present, and can store the host name hashed with `-HashHostName`.
`Remove-SSHKnownHost` rewrites the file atomically. `Get-SSHKnownHost`,
`Add-SSHKnownHost` and `Remove-SSHKnownHost` work on `~/.ssh/known_hosts` or on
the file given with `-Path`; they do not touch the system-wide files.

## Authentication

`New-SSHSession` builds its authentication methods as follows.

1. **`-KeyFile`**, optionally with `-KeyPassphrase` (a `SecureString`). The key
   file is loaded by SSH.NET and must load; a missing file or a wrong passphrase
   is an error.
2. **`-Credential`**. The password is offered with the `password` method and
   also with `keyboard-interactive`, because many servers only enable the
   latter. In `keyboard-interactive`, only prompts that contain the word
   "password" are answered.
3. **Default keys**, when neither of the above is given: the `IdentityFile`
   entries from the ssh config file, followed by `~/.ssh/id_ed25519`,
   `~/.ssh/id_ecdsa` and `~/.ssh/id_rsa`. All keys that load are offered. Keys
   that cannot be loaded, for example because they are protected by a
   passphrase, are skipped.

`-KeyFile` and `-Credential` cannot be combined in one call.

The user name is taken from `-UserName`, then from `user@host` in
`-ComputerName`, then from `-Credential`, then from `User` in the ssh config
file, and finally from the current local user name. The port is taken from
`-Port`, then from `host:port` in `-ComputerName`, then from `Port` in the ssh
config file, and is 22 otherwise.

### ssh config support

`New-SSHSession` reads `~/.ssh/config`, or the file given with `-ConfigFile`.
`-ConfigFile none` turns this off. The name given in `-ComputerName` (without
user and port) is matched against the `Host` patterns.

Honoured:

- `Host` blocks, with several patterns per line, the wildcards `*` and `?`, and
  negation with `!`
- `HostName`
- `User`
- `Port`
- `IdentityFile`, with `~` and the tokens `%d` (home directory) and `%h` (the
  host name as given)

As in OpenSSH, settings before the first `Host` line apply to every host, the
first value found for a keyword wins, and `IdentityFile` accumulates. Both
`Keyword value` and `Keyword=value` are accepted.

Everything else is ignored. In particular, `Include` is not followed, the
contents of `Match` blocks are skipped, and the system-wide `ssh_config` is not
read. `Get-SSHHostKey` does not read the config file.

## Key management

```powershell
# Ed25519 key pair, unencrypted
New-SSHKeyPair -Path ~/.ssh/id_ed25519

# RSA 4096 with a passphrase
$pass = Read-Host -AsSecureString -Prompt 'Passphrase'
New-SSHKeyPair -Path ~/.ssh/id_rsa -KeyType RSA -Passphrase $pass

Get-SSHKeyFingerprint -Path ~/.ssh/id_ed25519.pub
(ConvertTo-SSHPublicKey -Path ~/.ssh/id_ed25519).PublicKeyLine
Test-SSHKeyFile -Path ~/.ssh/id_ed25519
```

`New-SSHKeyPair` writes the private key in the OpenSSH private key format and
the public key to the same path with `.pub` appended.

| Key type | Sizes |
| --- | --- |
| Ed25519 (default) | fixed |
| RSA | 2048 to 16384 bits, in multiples of 8; default 4096 |
| ECDSA | 256 (default), 384 or 521 bits (NIST P-256, P-384, P-521) |

- The private key file is created empty, restricted to the current user (mode
  0600, or an owner-only ACL on Windows), and only then written. If the
  permissions cannot be applied, the file is removed and the command fails.
- With `-Passphrase` the private key is encrypted with aes256-ctr, using a key
  derived with bcrypt_pbkdf. OpenSSH reads these files.
- An existing private key file is not replaced unless `-Force` is given.

`Test-SSHKeyFile`, `ConvertTo-SSHPublicKey` and `Get-SSHKeyFingerprint` parse
two formats: OpenSSH private keys (`-----BEGIN OPENSSH PRIVATE KEY-----`) and
OpenSSH public key lines. `Test-SSHKeyFile` recognises PEM and PKCS#8 private
keys and PuTTY `.ppk` files and reports them as unsupported; the other two
commands fail on them.

## Compatibility with OpenSSH

### Supported

- **known_hosts**: plain and hashed host names, `[host]:port` entries, pattern
  lists with `*`, `?` and `!` negation, several keys per host, `@revoked` lines,
  trailing comments, the user files `known_hosts` and `known_hosts2`, and the
  system-wide `ssh_known_hosts` and `ssh_known_hosts2`.
- **Host key policy**: the equivalents of `StrictHostKeyChecking` `ask`, `yes`,
  `accept-new` and `no`. As in OpenSSH, `no` does not allow password
  authentication to a host whose key has changed.
- **Private keys**: the OpenSSH private key format for Ed25519, RSA and ECDSA
  (P-256, P-384, P-521), unencrypted or encrypted with aes256-ctr and
  bcrypt_pbkdf. Keys written by pwssh are read by `ssh-keygen`, and keys of
  these kinds written by `ssh-keygen` are read by pwssh.
- **Public keys and fingerprints**: OpenSSH public key lines; SHA256 and MD5
  fingerprints in the notation `ssh-keygen -l` uses.
- **ssh config**: `Host`, `HostName`, `User`, `Port` and `IdentityFile`.
- **Authentication**: public key, password, and keyboard-interactive for
  password prompts.
- **Port forwarding**: local (`-L`), remote (`-R`) and dynamic (`-D`).
- **Interactive shell**: Ctrl+C is sent to the remote program, the shell ends
  when the remote shell exits, and Enter followed by `~.` leaves a shell that
  no longer responds. The remote terminal follows changes of the local window
  size unless `-Columns` or `-Rows` is given.

Key exchange methods, ciphers, MACs and host key algorithms are those of
SSH.NET 2024.2.0. pwssh does not configure them.

### Limitations

- No ssh-agent support. Keys are read from files only.
- No host or user certificates. `@cert-authority` lines in `known_hosts` are
  ignored.
- No `ProxyJump` or `ProxyCommand`.
- ssh config support is limited to `Host`, `HostName`, `User`, `Port` and
  `IdentityFile`. `Match` and `Include` are ignored, and so is every other
  keyword.
- The key commands (`New-SSHKeyPair`, `Test-SSHKeyFile`,
  `ConvertTo-SSHPublicKey`, `Get-SSHKeyFingerprint`) handle only OpenSSH-format
  private keys. Connecting with a key in another format (`-KeyFile`) depends on
  what SSH.NET itself can load.
- For encrypted private keys, the key commands support only aes256-ctr with
  bcrypt.
- Passphrase-protected default keys in `~/.ssh` are skipped. To use such a key,
  pass it with `-KeyFile` and `-KeyPassphrase`.
- Ed25519 key generation uses a `BigInteger` implementation that is not
  constant time. It is used only for generating keys locally. Signing during
  authentication is done by SSH.NET.
- Terminal resizing in `Enter-SSHSession` relies on SSH.NET internals and is
  best effort.
- `Enter-SSHSession` needs an interactive console and does not work with
  redirected input.
- Keyboard-interactive authentication only answers password prompts. One-time
  codes and other challenges are not supported.
- A server that presents a host key of a different type than the one recorded
  for it is treated as changed. pwssh does not ask the server for the key type
  that is already in `known_hosts`.
- Host keys recorded by `New-SSHSession` are stored with the plain host name.
  Use `Add-SSHKnownHost -HashHostName` for a hashed entry.
- `Send-SFTPFile` and `Receive-SFTPFile` transfer single files. Directories can
  be copied with the SCP commands and `-Recurse`.
- `Invoke-SSHCommand` runs the command on the given sessions one after the
  other, not in parallel.

## Testing

```powershell
./build.ps1 -Task Test          # unit tests
./build.ps1 -Task Integration   # integration tests
```

Results are written to `./TestResults`.

The unit tests (`Tests/Unit`) do not need an SSH server. The tests that hand
generated keys to `ssh-keygen` are skipped when `ssh-keygen` is not installed.

The integration tests (`Tests/Integration`) drive the built module against a
real OpenSSH server. There are two ways to run them:

1. **Self-hosted**, the default on Linux and macOS when `sshd` and `ssh-keygen`
   are installed. The tests start a private `sshd` on a free loopback port,
   running as the current user, with throwaway host keys and a throwaway
   `known_hosts` file. Nothing in `~/.ssh` is read or written. Only public key
   authentication is exercised.
2. **External server**. Set these environment variables and the tests use that
   server instead:

   | Variable | Meaning |
   | --- | --- |
   | `PWSSH_TEST_HOST` | Host name. Setting it selects this mode. |
   | `PWSSH_TEST_PORT` | Port (default 22) |
   | `PWSSH_TEST_USER` | User name |
   | `PWSSH_TEST_KEYFILE` | Unencrypted private key accepted by the server |
   | `PWSSH_TEST_PASSWORD` | Password; optional, enables the password tests |

   The tests that change the server's host key are skipped in this mode.

If neither mode is available (for example on Windows without
`PWSSH_TEST_HOST`), all integration tests are skipped and
`./build.ps1 -Task Integration` fails with "nothing ran".

The CI workflow (`.github/workflows/ci.yml`) runs the unit tests on Windows
PowerShell 5.1 and on PowerShell 7 on Windows, Ubuntu and macOS, imports the
built module on each of them, and runs the integration tests on Ubuntu.

## Licence

The module manifest (`src/pwssh/pwssh.psd1`) declares the MIT licence. The
repository does not contain a LICENSE file yet.

See [CHANGELOG.md](CHANGELOG.md) for the release history.
