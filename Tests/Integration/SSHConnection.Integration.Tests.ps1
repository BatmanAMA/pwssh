<#
.SYNOPSIS
    Integration tests for pwssh: the built module against a real OpenSSH server.
.DESCRIPTION
    Two ways to run:

    1. Self-hosted (default on Linux/macOS when sshd and ssh-keygen are installed):
       the tests start a private sshd on a free loopback port, running as the current
       user, with throwaway host keys and a throwaway known_hosts file. Nothing in
       ~/.ssh is read or written. Only public key authentication is exercised.

    2. External server: set these variables and the tests use that server instead.
         $env:PWSSH_TEST_HOST      host name
         $env:PWSSH_TEST_PORT      port (default 22)
         $env:PWSSH_TEST_USER      user name
         $env:PWSSH_TEST_KEYFILE   private key (unencrypted) accepted by the server
         $env:PWSSH_TEST_PASSWORD  password, enables the password tests (optional)
       Host-key-change tests are skipped in this mode.

    Requires the dependencies: run ./build.ps1 first (or ./build.ps1 -Task Integration).
#>

BeforeDiscovery {
    $script:External = [bool]$env:PWSSH_TEST_HOST
    $sshd = Get-Command sshd -ErrorAction SilentlyContinue
    if (-not $sshd) { $sshd = Get-Item '/usr/sbin/sshd' -ErrorAction SilentlyContinue }
    $onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows
    $script:SelfHosted = (-not $script:External) -and (-not $onWindows) -and $sshd -and
        (Get-Command ssh-keygen -ErrorAction SilentlyContinue)
    $script:CanRun = $script:External -or $script:SelfHosted
    $script:HasPassword = $script:External -and [bool]$env:PWSSH_TEST_PASSWORD
}

BeforeAll {
    $repoRoot = Join-Path (Join-Path $PSScriptRoot '..') '..'
    $built = Join-Path (Join-Path (Join-Path $repoRoot 'output') 'pwssh') 'pwssh.psd1'
    $source = Join-Path (Join-Path (Join-Path $repoRoot 'src') 'pwssh') 'pwssh.psd1'
    $manifest = if (Test-Path $built) { $built } else { $source }
    Import-Module $manifest -Force

    $script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_it_$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    New-Item -Path $script:WorkDir -ItemType Directory -Force | Out-Null
    $script:KnownHosts = Join-Path $script:WorkDir 'known_hosts'
    $script:SshdProcess = $null

    function Start-TestSshd {
        # (Re)start the private sshd with the given host key file
        param([string]$HostKeyName)

        Stop-TestSshd
        $config = Join-Path $script:WorkDir 'sshd_config'
        @(
            "Port $script:TestPort"
            'ListenAddress 127.0.0.1'
            "HostKey $(Join-Path $script:WorkDir $HostKeyName)"
            "AuthorizedKeysFile $(Join-Path $script:WorkDir 'authorized_keys')"
            "PidFile $(Join-Path $script:WorkDir 'sshd.pid')"
            'StrictModes no'
            'UsePAM no'
            'PasswordAuthentication no'
            'KbdInteractiveAuthentication no'
            'PubkeyAuthentication yes'
            'PermitRootLogin yes'
            'Subsystem sftp internal-sftp'
        ) | Set-Content -LiteralPath $config

        $sshdPath = (Get-Command sshd -ErrorAction SilentlyContinue).Source
        if (-not $sshdPath) { $sshdPath = '/usr/sbin/sshd' }
        $log = Join-Path $script:WorkDir 'sshd.log'
        # -D: stay in the foreground so we own the process; -e: log to stderr
        $script:SshdProcess = Start-Process -FilePath $sshdPath -ArgumentList '-D', '-e', '-f', $config `
            -RedirectStandardError $log -RedirectStandardOutput (Join-Path $script:WorkDir 'sshd.out') -PassThru

        # Wait until it accepts connections
        $deadline = [datetime]::UtcNow.AddSeconds(15)
        while ([datetime]::UtcNow -lt $deadline) {
            if ($script:SshdProcess.HasExited) {
                throw "sshd exited: $(Get-Content $log -Raw -ErrorAction SilentlyContinue)"
            }
            $probe = [System.Net.Sockets.TcpClient]::new()
            try { $probe.Connect('127.0.0.1', $script:TestPort); return }
            catch { Start-Sleep -Milliseconds 100 }
            finally { $probe.Dispose() }
        }
        throw "sshd did not start listening on port $script:TestPort"
    }

    function Stop-TestSshd {
        if ($script:SshdProcess -and -not $script:SshdProcess.HasExited) {
            # Stops the listener only; established connections live in their own processes
            $script:SshdProcess.Kill()
            $script:SshdProcess.WaitForExit(5000) | Out-Null
        }
        $script:SshdProcess = $null
    }

    function Connect-Test {
        # New-SSHSession against the test server with the isolated known_hosts
        param([hashtable]$Extra = @{})
        $params = @{
            ComputerName   = $script:TestHost
            Port           = $script:TestPort
            UserName       = $script:TestUser
            KeyFile        = $script:TestKeyFile
            KnownHostsPath = $script:KnownHosts
            ConfigFile     = 'none'
        }
        foreach ($k in $Extra.Keys) { $params[$k] = $Extra[$k] }
        New-SSHSession @params
    }

    if ($env:PWSSH_TEST_HOST) {
        $script:TestHost    = $env:PWSSH_TEST_HOST
        $script:TestPort    = if ($env:PWSSH_TEST_PORT) { [int]$env:PWSSH_TEST_PORT } else { 22 }
        $script:TestUser    = $env:PWSSH_TEST_USER
        $script:TestKeyFile = $env:PWSSH_TEST_KEYFILE
    }
    elseif (-not (($PSVersionTable.PSEdition -eq 'Desktop') -or $IsWindows) -and (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        $script:TestHost = '127.0.0.1'
        $script:TestUser = [System.Environment]::UserName

        # A free loopback port
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $script:TestPort = $listener.LocalEndpoint.Port
        $listener.Stop()

        # Two host keys, so the server's identity can be changed mid-test
        foreach ($name in 'hostkey_a', 'hostkey_b') {
            & ssh-keygen -q -t ed25519 -N '' -f (Join-Path $script:WorkDir $name)
        }

        # Client keys generated by the module itself: one per type, one encrypted
        $script:KeyPass = ConvertTo-SecureString 'integration pass' -AsPlainText -Force
        $script:TestKeyFile = Join-Path $script:WorkDir 'id_ed25519'
        $null = New-SSHKeyPair -Path $script:TestKeyFile -KeyType Ed25519 -Comment 'it-ed25519'
        $null = New-SSHKeyPair -Path (Join-Path $script:WorkDir 'id_rsa') -KeyType RSA -KeySize 2048 -Comment 'it-rsa'
        $null = New-SSHKeyPair -Path (Join-Path $script:WorkDir 'id_ecdsa') -KeyType ECDSA -Comment 'it-ecdsa'
        $null = New-SSHKeyPair -Path (Join-Path $script:WorkDir 'id_enc') -KeyType Ed25519 -Comment 'it-enc' -Passphrase $script:KeyPass
        $null = New-SSHKeyPair -Path (Join-Path $script:WorkDir 'id_unauthorized') -Comment 'it-unauthorized'

        Get-Content (Join-Path $script:WorkDir 'id_ed25519.pub'), (Join-Path $script:WorkDir 'id_rsa.pub'),
                    (Join-Path $script:WorkDir 'id_ecdsa.pub'), (Join-Path $script:WorkDir 'id_enc.pub') |
            Set-Content -LiteralPath (Join-Path $script:WorkDir 'authorized_keys')

        Start-TestSshd -HostKeyName 'hostkey_a'
    }
}

AfterAll {
    Get-SSHSession -ErrorAction SilentlyContinue | Remove-SSHSession -Confirm:$false -ErrorAction SilentlyContinue
    if (Get-Command Stop-TestSshd -ErrorAction SilentlyContinue) { Stop-TestSshd }
    Remove-Module pwssh -Force -ErrorAction SilentlyContinue
    if ($script:WorkDir) { Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'pwssh against a real SSH server' -Tag 'Integration' -Skip:(-not $script:CanRun) {

    Context 'Host key verification on first contact' {
        BeforeEach {
            Remove-Item -LiteralPath $script:KnownHosts -Force -ErrorAction SilentlyContinue
        }

        It 'retrieves the host key without authenticating' {
            $key = Get-SSHHostKey -ComputerName $script:TestHost -Port $script:TestPort
            $key.KeyType | Should -Not -BeNullOrEmpty
            $key.Fingerprint | Should -BeLike 'SHA256:*'
            $key.RawKey.Length | Should -BeGreaterThan 0
        }

        It 'refuses an unknown host with StrictHostKeyChecking Yes' {
            { Connect-Test @{ StrictHostKeyChecking = 'Yes'; ErrorAction = 'Stop' } } | Should -Throw '*Host key verification failed*'
            Test-Path $script:KnownHosts | Should -BeFalse
        }

        It 'refuses an unknown host when it cannot prompt' {
            Mock -ModuleName pwssh Read-Host { throw 'non-interactive' }
            { Connect-Test @{ ErrorAction = 'Stop' } } | Should -Throw '*cannot prompt*'
            Test-Path $script:KnownHosts | Should -BeFalse
        }

        It 'refuses an unknown host when the user answers no' {
            Mock -ModuleName pwssh Read-Host { 'no' }
            { Connect-Test @{ ErrorAction = 'Stop' } } | Should -Throw '*not accepted*'
            Test-Path $script:KnownHosts | Should -BeFalse
        }

        It 'connects and records the key when the user answers yes' {
            Mock -ModuleName pwssh Read-Host { 'yes' }
            $session = Connect-Test @{ WarningAction = 'SilentlyContinue' }
            try {
                $session.Connected | Should -BeTrue
                @(Get-SSHKnownHost -Path $script:KnownHosts -HostName $script:TestHost -Port $script:TestPort).Count | Should -Be 1
            }
            finally { $session | Remove-SSHSession -Confirm:$false }
        }

        It 'connects and records the key with -AcceptKey' {
            $session = Connect-Test @{ AcceptKey = $true; WarningAction = 'SilentlyContinue' }
            try {
                $session.Connected | Should -BeTrue
                $session.HostKeyFingerprint | Should -Be (Get-SSHHostKey $script:TestHost -Port $script:TestPort).Fingerprint
                $recorded = @(Get-SSHKnownHost -Path $script:KnownHosts)
                $recorded.Count | Should -Be 1
                $recorded[0].Fingerprint | Should -Be $session.HostKeyFingerprint
            }
            finally { $session | Remove-SSHSession -Confirm:$false }
        }

        It 'accepts a key added with Get-SSHHostKey | Add-SSHKnownHost -HashHostName' {
            Get-SSHHostKey $script:TestHost -Port $script:TestPort | Add-SSHKnownHost -Path $script:KnownHosts -HashHostName
            Get-Content $script:KnownHosts | Should -BeLike '|1|*'
            $session = Connect-Test @{ StrictHostKeyChecking = 'Yes' }
            try { $session.Connected | Should -BeTrue }
            finally { $session | Remove-SSHSession -Confirm:$false }
        }
    }

    Context 'Sessions, commands and transfers' {
        BeforeAll {
            Remove-Item -LiteralPath $script:KnownHosts -Force -ErrorAction SilentlyContinue
            $script:Session = Connect-Test @{ AcceptKey = $true; WarningAction = 'SilentlyContinue' }
            $script:RemoteDir = "/tmp/pwssh_it_$([guid]::NewGuid().ToString('N').Substring(0, 12))"
            $null = Invoke-SSHCommand -SessionId $script:Session.SessionId -Command "mkdir -p '$script:RemoteDir'"
        }
        AfterAll {
            if ($script:Session) {
                $null = Invoke-SSHCommand -SessionId $script:Session.SessionId -Command "rm -rf '$script:RemoteDir'" -ErrorAction SilentlyContinue
                $script:Session | Remove-SSHSession -Confirm:$false -ErrorAction SilentlyContinue
            }
        }

        It 'reconnects to a known host in strict mode' {
            $again = Connect-Test @{ StrictHostKeyChecking = 'Yes' }
            try { $again.Connected | Should -BeTrue }
            finally { $again | Remove-SSHSession -Confirm:$false }
        }

        It 'lists the session' {
            (Get-SSHSession -SessionId $script:Session.SessionId).ComputerName | Should -Be $script:TestHost
        }

        It 'runs a command and returns its output' {
            $r = Invoke-SSHCommand -SessionId $script:Session.SessionId -Command 'echo hello-pwssh'
            $r.Output.Trim() | Should -Be 'hello-pwssh'
            $r.ExitCode | Should -Be 0
            $r.Success | Should -BeTrue
        }

        It 'reports a non-zero exit code and stderr' {
            $r = Invoke-SSHCommand -SessionId $script:Session.SessionId -Command 'echo oops >&2; exit 7'
            $r.ExitCode | Should -Be 7
            $r.Success | Should -BeFalse
            $r.Error.Trim() | Should -Be 'oops'
        }

        It 'accepts sessions from the pipeline' {
            ($script:Session | Invoke-SSHCommand -Command 'echo piped').Output.Trim() | Should -Be 'piped'
        }

        It 'round-trips a file over SFTP, using relative local paths' {
            $local = Join-Path $script:WorkDir 'sftp_src.bin'
            $bytes = [byte[]]::new(200KB); [System.Random]::new(1).NextBytes($bytes)
            [System.IO.File]::WriteAllBytes($local, $bytes)

            Push-Location $script:WorkDir
            try {
                Send-SFTPFile -SessionId $script:Session.SessionId -LocalPath 'sftp_src.bin' -RemotePath "$script:RemoteDir/sftp.bin"
                Receive-SFTPFile -SessionId $script:Session.SessionId -RemotePath "$script:RemoteDir/sftp.bin" -LocalPath 'sftp_back.bin'
            }
            finally { Pop-Location }

            (Get-FileHash (Join-Path $script:WorkDir 'sftp_back.bin')).Hash | Should -Be (Get-FileHash $local).Hash
            (Get-SFTPChildItem -SessionId $script:Session.SessionId -Path $script:RemoteDir).Name | Should -Contain 'sftp.bin'
        }

        It 'does not overwrite a local file without -Overwrite' {
            $existing = Join-Path $script:WorkDir 'keep.txt'
            Set-Content -LiteralPath $existing -Value 'original'
            { Receive-SFTPFile -SessionId $script:Session.SessionId -RemotePath "$script:RemoteDir/sftp.bin" -LocalPath $existing -ErrorAction Stop } |
                Should -Throw '*already exists*'
            Get-Content $existing | Should -Be 'original'
        }

        It 'leaves no partial file when an SFTP download fails' {
            $target = Join-Path $script:WorkDir 'missing_download.bin'
            Receive-SFTPFile -SessionId $script:Session.SessionId -RemotePath "$script:RemoteDir/does-not-exist" -LocalPath $target -ErrorAction SilentlyContinue
            Test-Path $target | Should -BeFalse
            @(Get-ChildItem $script:WorkDir -Filter '*.part').Count | Should -Be 0
        }

        It 'round-trips a file over SCP' {
            $local = Join-Path $script:WorkDir 'scp_src.txt'
            Set-Content -LiteralPath $local -Value 'scp payload'
            Send-SCPFile -SessionId $script:Session.SessionId -LocalPath $local -RemotePath "$script:RemoteDir/scp.txt"
            $back = Join-Path $script:WorkDir 'scp_back.txt'
            Receive-SCPFile -SessionId $script:Session.SessionId -RemotePath "$script:RemoteDir/scp.txt" -LocalPath $back
            Get-Content $back | Should -Be 'scp payload'
        }

        It 'forwards a local port' {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start(); $localPort = $listener.LocalEndpoint.Port; $listener.Stop()

            $forward = New-SSHPortForward -SessionId $script:Session.SessionId -Type Local -BoundPort $localPort `
                -RemoteHost '127.0.0.1' -RemotePort $script:TestPort
            try {
                $forward.IsStarted | Should -BeTrue
                $forward.BoundHost | Should -Be 'localhost'
                $tcp = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $localPort)
                try {
                    $tcp.ReceiveTimeout = 5000
                    $buffer = [byte[]]::new(8)
                    $read = $tcp.GetStream().Read($buffer, 0, 8)
                    [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read) | Should -BeLike 'SSH-2.0*'
                }
                finally { $tcp.Dispose() }
            }
            finally { Remove-SSHPortForward -ForwardId $forward.ForwardId -Confirm:$false }
            Get-SSHPortForward | Where-Object ForwardId -eq $forward.ForwardId | Should -BeNullOrEmpty
        }

        It 'removes the session' {
            $temp = Connect-Test
            Remove-SSHSession -SessionId $temp.SessionId -Confirm:$false
            Get-SSHSession | Where-Object SessionId -eq $temp.SessionId | Should -BeNullOrEmpty
        }
    }

    Context 'Keys generated by New-SSHKeyPair authenticate' -Skip:(-not $script:SelfHosted) {
        It 'authenticates with a <Name> key' -ForEach @(
            @{ Name = 'RSA';   File = 'id_rsa' }
            @{ Name = 'ECDSA'; File = 'id_ecdsa' }
        ) {
            $session = Connect-Test @{ KeyFile = (Join-Path $script:WorkDir $File); AcceptKey = $true; WarningAction = 'SilentlyContinue' }
            try { $session.Connected | Should -BeTrue }
            finally { $session | Remove-SSHSession -Confirm:$false }
        }

        It 'authenticates with a passphrase-protected key' {
            $session = Connect-Test @{ KeyFile = (Join-Path $script:WorkDir 'id_enc'); KeyPassphrase = $script:KeyPass; AcceptKey = $true; WarningAction = 'SilentlyContinue' }
            try { $session.Connected | Should -BeTrue }
            finally { $session | Remove-SSHSession -Confirm:$false }
        }

        It 'fails cleanly with a key the server does not know' {
            { Connect-Test @{ KeyFile = (Join-Path $script:WorkDir 'id_unauthorized'); AcceptKey = $true; ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' } } |
                Should -Throw '*Permission denied*'
        }

        It 'reads HostName, Port, User and IdentityFile from an ssh config file' {
            $config = Join-Path $script:WorkDir 'ssh_config'
            @(
                'Host testbox'
                "    HostName $script:TestHost"
                "    Port $script:TestPort"
                "    User $script:TestUser"
                "    IdentityFile $script:TestKeyFile"
            ) | Set-Content -LiteralPath $config
            $session = New-SSHSession -ComputerName testbox -ConfigFile $config -KnownHostsPath $script:KnownHosts -AcceptKey -WarningAction SilentlyContinue
            try {
                $session.Connected | Should -BeTrue
                $session.ComputerName | Should -Be $script:TestHost
                $session.Port | Should -Be $script:TestPort
            }
            finally { $session | Remove-SSHSession -Confirm:$false }
        }
    }

    Context 'Password authentication' -Skip:(-not $script:HasPassword) {
        It 'connects with a password credential' {
            $cred = [pscredential]::new($script:TestUser, (ConvertTo-SecureString $env:PWSSH_TEST_PASSWORD -AsPlainText -Force))
            $session = New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -Credential $cred `
                -KnownHostsPath $script:KnownHosts -ConfigFile none -AcceptKey -WarningAction SilentlyContinue
            try {
                $session.Connected | Should -BeTrue
                $session.AuthMethod | Should -Be 'Password'
            }
            finally { $session | Remove-SSHSession -Confirm:$false }
        }
    }

    # Keep this context last: it replaces the server's host key.
    Context 'A server whose host key changes' -Skip:(-not $script:SelfHosted) {
        BeforeAll {
            Remove-Item -LiteralPath $script:KnownHosts -Force -ErrorAction SilentlyContinue
            # Established while the server still presents host key A; no SFTP/SCP opened yet
            $script:Before = Connect-Test @{ AcceptKey = $true; WarningAction = 'SilentlyContinue' }
            Start-TestSshd -HostKeyName 'hostkey_b'
        }
        AfterAll {
            if ($script:Before) { $script:Before | Remove-SSHSession -Confirm:$false -ErrorAction SilentlyContinue }
        }

        It 'refuses to connect in <Mode> mode' -ForEach @(
            @{ Mode = 'Ask' }, @{ Mode = 'Yes' }, @{ Mode = 'AcceptNew' }
        ) {
            { Connect-Test @{ StrictHostKeyChecking = $Mode; ErrorAction = 'Stop' } } |
                Should -Throw '*REMOTE HOST IDENTIFICATION HAS CHANGED*'
        }

        It 'refuses to connect with -AcceptKey' {
            { Connect-Test @{ AcceptKey = $true; ErrorAction = 'Stop' } } |
                Should -Throw '*REMOTE HOST IDENTIFICATION HAS CHANGED*'
        }

        It 'does not replace the recorded key' {
            $recorded = @(Get-SSHKnownHost -Path $script:KnownHosts)
            $recorded.Count | Should -Be 1
            $recorded[0].Fingerprint | Should -Be $script:Before.HostKeyFingerprint
        }

        It 'refuses password authentication even with StrictHostKeyChecking No' {
            $cred = [pscredential]::new($script:TestUser, (ConvertTo-SecureString 'not-the-password' -AsPlainText -Force))
            { New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -Credential $cred -StrictHostKeyChecking No `
                -KnownHostsPath $script:KnownHosts -ConfigFile none -ErrorAction Stop } |
                Should -Throw '*Password authentication is disabled*'
        }

        It 'refuses to open SFTP on the existing session (key is pinned)' {
            { Get-SFTPChildItem -SessionId $script:Before.SessionId -Path '/tmp' -ErrorAction Stop } |
                Should -Throw '*different host key*'
        }

        It 'refuses to open SCP on the existing session (key is pinned)' {
            $local = Join-Path $script:WorkDir 'pinned.txt'
            Set-Content -LiteralPath $local -Value 'x'
            { Send-SCPFile -SessionId $script:Before.SessionId -LocalPath $local -RemotePath '/tmp/pwssh_pinned.txt' -ErrorAction Stop } |
                Should -Throw '*different host key*'
        }

        It 'keeps the already established session usable' {
            (Invoke-SSHCommand -SessionId $script:Before.SessionId -Command 'echo still-here').Output.Trim() | Should -Be 'still-here'
        }

        It 'connects again once the stale entry is removed' {
            Remove-SSHKnownHost -HostName $script:TestHost -Port $script:TestPort -Path $script:KnownHosts -Confirm:$false
            $session = Connect-Test @{ AcceptKey = $true; WarningAction = 'SilentlyContinue' }
            try {
                $session.Connected | Should -BeTrue
                $session.HostKeyFingerprint | Should -Not -Be $script:Before.HostKeyFingerprint
            }
            finally { $session | Remove-SSHSession -Confirm:$false }
        }
    }
}
