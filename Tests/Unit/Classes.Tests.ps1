BeforeAll {
    # Dot-source the class files directly for unit testing
    $classPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Classes'
    . (Join-Path $classPath 'SSHHostKey.ps1')
    . (Join-Path $classPath 'SSHKnownHost.ps1')
    . (Join-Path $classPath 'SSHCommandResult.ps1')
    . (Join-Path $classPath 'SSHPortForward.ps1')
    . (Join-Path $classPath 'SSHSession.ps1')
}

Describe 'SSHSessionInfo' {
    It 'has default port of 22' {
        $session = [SSHSessionInfo]::new()
        $session.Port | Should -Be 22
    }

    It 'sets ConnectedAt on creation' {
        $before = [datetime]::UtcNow
        $session = [SSHSessionInfo]::new()
        $after = [datetime]::UtcNow
        $session.ConnectedAt | Should -BeGreaterOrEqual $before
        $session.ConnectedAt | Should -BeLessOrEqual $after
    }

    It 'ToString shows Open when Connected is true' {
        $session = [SSHSessionInfo]::new()
        $session.SessionId = 1
        $session.UserName = 'admin'
        $session.ComputerName = 'server01'
        $session.Port = 22
        $session.Connected = $true
        $session.ToString() | Should -BeLike '*Open*'
    }

    It 'ToString shows Closed when Connected is false' {
        $session = [SSHSessionInfo]::new()
        $session.SessionId = 2
        $session.UserName = 'root'
        $session.ComputerName = 'db01'
        $session.Connected = $false
        $session.ToString() | Should -BeLike '*Closed*'
    }

    It 'ToString includes user@host:port format' {
        $session = [SSHSessionInfo]::new()
        $session.SessionId = 3
        $session.UserName = 'deploy'
        $session.ComputerName = 'web.example.com'
        $session.Port = 2222
        $session.Connected = $true
        $result = $session.ToString()
        $result | Should -BeLike '*deploy@web.example.com:2222*'
    }

    It 'can store all expected properties' {
        $session = [SSHSessionInfo]::new()
        $session.SessionId = 10
        $session.ComputerName = 'test-host'
        $session.Port = 443
        $session.UserName = 'testuser'
        $session.AuthMethod = 'PublicKey'
        $session.Connected = $true
        $session.ServerVersion = 'SSH-2.0-OpenSSH_9.0'
        $session.ClientVersion = 'SSH-2.0-Renci.SshNet'

        $session.SessionId | Should -Be 10
        $session.ComputerName | Should -Be 'test-host'
        $session.Port | Should -Be 443
        $session.UserName | Should -Be 'testuser'
        $session.AuthMethod | Should -Be 'PublicKey'
        $session.ServerVersion | Should -Be 'SSH-2.0-OpenSSH_9.0'
    }
}

Describe 'SSHCommandResult' {
    It 'creates a new instance' {
        $result = [SSHCommandResult]::new()
        $result | Should -Not -BeNullOrEmpty
    }

    It 'stores command execution details' {
        $result = [SSHCommandResult]::new()
        $result.SessionId = 1
        $result.ComputerName = 'server01'
        $result.Command = 'uname -a'
        $result.ExitCode = 0
        $result.Output = 'Linux server01 5.15.0'
        $result.Error = ''
        $result.Duration = [timespan]::FromMilliseconds(150)

        $result.Command | Should -Be 'uname -a'
        $result.ExitCode | Should -Be 0
        $result.Output | Should -Be 'Linux server01 5.15.0'
    }

    It 'ToString returns the output' {
        $result = [SSHCommandResult]::new()
        $result.Output = 'hello world'
        $result.ToString() | Should -Be 'hello world'
    }

    It 'handles empty output' {
        $result = [SSHCommandResult]::new()
        $result.Output = ''
        $result.ToString() | Should -Be ''
    }

    It 'tracks start and end time' {
        $result = [SSHCommandResult]::new()
        $start = [datetime]::UtcNow
        $result.StartTime = $start
        $result.EndTime = $start.AddSeconds(2)
        $result.Duration = $result.EndTime - $result.StartTime
        $result.Duration.TotalSeconds | Should -Be 2
    }
}

Describe 'SSHPortForward' {
    It 'creates a new instance' {
        $fwd = [SSHPortForward]::new()
        $fwd | Should -Not -BeNullOrEmpty
    }

    It 'ToString for Local forward' {
        $fwd = [SSHPortForward]::new()
        $fwd.Type = 'Local'
        $fwd.BoundHost = 'localhost'
        $fwd.BoundPort = 8080
        $fwd.RemoteHost = 'db.internal'
        $fwd.RemotePort = 5432
        $fwd.ToString() | Should -Be 'L:localhost:8080 -> db.internal:5432'
    }

    It 'ToString for Remote forward' {
        $fwd = [SSHPortForward]::new()
        $fwd.Type = 'Remote'
        $fwd.BoundHost = 'localhost'
        $fwd.BoundPort = 9090
        $fwd.RemoteHost = '0.0.0.0'
        $fwd.RemotePort = 80
        $fwd.ToString() | Should -Be 'R:0.0.0.0:80 -> localhost:9090'
    }

    It 'ToString for Dynamic forward' {
        $fwd = [SSHPortForward]::new()
        $fwd.Type = 'Dynamic'
        $fwd.BoundHost = 'localhost'
        $fwd.BoundPort = 1080
        $fwd.ToString() | Should -Be 'D:localhost:1080'
    }

    It 'stores all properties' {
        $fwd = [SSHPortForward]::new()
        $fwd.ForwardId = 5
        $fwd.SessionId = 2
        $fwd.Type = 'Local'
        $fwd.BoundHost = '127.0.0.1'
        $fwd.BoundPort = 3000
        $fwd.RemoteHost = 'app-server'
        $fwd.RemotePort = 8080
        $fwd.IsStarted = $true

        $fwd.ForwardId | Should -Be 5
        $fwd.SessionId | Should -Be 2
        $fwd.IsStarted | Should -BeTrue
    }
}

Describe 'SSHHostKey' {
    It 'has default port of 22' {
        $key = [SSHHostKey]::new()
        $key.Port | Should -Be 22
    }

    It 'stores key information' {
        $key = [SSHHostKey]::new()
        $key.ComputerName = 'github.com'
        $key.KeyType = 'ssh-ed25519'
        $key.Fingerprint = 'SHA256:abcdef123456'
        $key.KeyLength = 256
        $key.RawKey = [byte[]]@(1, 2, 3, 4)

        $key.ComputerName | Should -Be 'github.com'
        $key.KeyType | Should -Be 'ssh-ed25519'
        $key.KeyLength | Should -Be 256
    }

    It 'ToString includes host and key type' {
        $key = [SSHHostKey]::new()
        $key.ComputerName = 'example.com'
        $key.KeyType = 'ssh-rsa'
        $key.Fingerprint = 'SHA256:xyz'
        $result = $key.ToString()
        $result | Should -BeLike '*example.com*'
        $result | Should -BeLike '*ssh-rsa*'
    }
}

Describe 'SSHKnownHost' {
    It 'has default port of 22' {
        $kh = [SSHKnownHost]::new()
        $kh.Port | Should -Be 22
    }

    It 'ToKnownHostsLine for standard port' {
        $kh = [SSHKnownHost]::new()
        $kh.HostName = 'server01'
        $kh.Port = 22
        $kh.KeyType = 'ssh-ed25519'
        $kh.KeyData = 'AAAAC3NzaC1lZDI1NTE5AAAAIG...'
        $line = $kh.ToKnownHostsLine()
        $line | Should -Be 'server01 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG...'
    }

    It 'ToKnownHostsLine for non-standard port' {
        $kh = [SSHKnownHost]::new()
        $kh.HostName = '10.0.0.1'
        $kh.Port = 2222
        $kh.KeyType = 'ssh-rsa'
        $kh.KeyData = 'AAAAB3Nza...'
        $line = $kh.ToKnownHostsLine()
        $line | Should -Be '[10.0.0.1]:2222 ssh-rsa AAAAB3Nza...'
    }

    It 'ToString shows hostname and key type' {
        $kh = [SSHKnownHost]::new()
        $kh.HostName = 'myhost'
        $kh.KeyType = 'ecdsa-sha2-nistp256'
        $kh.ToString() | Should -Be 'myhost ecdsa-sha2-nistp256'
    }

    It 'stores source file and line number' {
        $kh = [SSHKnownHost]::new()
        $kh.Source = '/home/user/.ssh/known_hosts'
        $kh.LineNumber = 42
        $kh.Source | Should -Be '/home/user/.ssh/known_hosts'
        $kh.LineNumber | Should -Be 42
    }
}
