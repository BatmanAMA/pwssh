BeforeAll {
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Private' 'Resolve-SSHHostName.ps1')
}

Describe 'Resolve-SSHHostName' {
    It 'parses a simple hostname' {
        $result = Resolve-SSHHostName -Target 'server01'
        $result.ComputerName | Should -Be 'server01'
        $result.Port | Should -Be 22
        $result.UserName | Should -BeNullOrEmpty
    }

    It 'parses user@host' {
        $result = Resolve-SSHHostName -Target 'admin@server01'
        $result.UserName | Should -Be 'admin'
        $result.ComputerName | Should -Be 'server01'
        $result.Port | Should -Be 22
    }

    It 'parses host:port' {
        $result = Resolve-SSHHostName -Target 'server01:2222'
        $result.ComputerName | Should -Be 'server01'
        $result.Port | Should -Be 2222
        $result.UserName | Should -BeNullOrEmpty
    }

    It 'parses user@host:port' {
        $result = Resolve-SSHHostName -Target 'root@10.0.0.1:22222'
        $result.UserName | Should -Be 'root'
        $result.ComputerName | Should -Be '10.0.0.1'
        $result.Port | Should -Be 22222
    }

    It 'parses IPv6 address [host]:port' {
        $result = Resolve-SSHHostName -Target '[::1]:2222'
        $result.ComputerName | Should -Be '::1'
        $result.Port | Should -Be 2222
    }

    It 'parses IPv6 address [host] without port' {
        $result = Resolve-SSHHostName -Target '[fe80::1]'
        $result.ComputerName | Should -Be 'fe80::1'
        $result.Port | Should -Be 22
    }

    It 'parses user@[host]:port' {
        $result = Resolve-SSHHostName -Target 'admin@[::1]:9999'
        $result.UserName | Should -Be 'admin'
        $result.ComputerName | Should -Be '::1'
        $result.Port | Should -Be 9999
    }

    It 'uses custom default port' {
        $result = Resolve-SSHHostName -Target 'myhost' -DefaultPort 443
        $result.Port | Should -Be 443
    }

    It 'parses FQDN' {
        $result = Resolve-SSHHostName -Target 'deploy@web.prod.example.com:2200'
        $result.UserName | Should -Be 'deploy'
        $result.ComputerName | Should -Be 'web.prod.example.com'
        $result.Port | Should -Be 2200
    }

    It 'handles IP address without user' {
        $result = Resolve-SSHHostName -Target '192.168.1.100'
        $result.ComputerName | Should -Be '192.168.1.100'
        $result.UserName | Should -BeNullOrEmpty
        $result.Port | Should -Be 22
    }
}
