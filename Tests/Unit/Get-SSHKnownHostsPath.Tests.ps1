BeforeAll {
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Private' 'Get-SSHKnownHostsPath.ps1')
}

Describe 'Get-SSHKnownHostsPath' {
    It 'returns the supplied path when provided' {
        $result = Get-SSHKnownHostsPath -Path '/tmp/test_known_hosts'
        $result | Should -Be '/tmp/test_known_hosts'
    }

    It 'returns default path under HOME/.ssh when no path supplied' {
        $result = Get-SSHKnownHostsPath
        $expected = Join-Path $HOME '.ssh' 'known_hosts'
        $result | Should -Be $expected
    }

    It 'returns default path when Path is empty string' {
        $result = Get-SSHKnownHostsPath -Path ''
        $expected = Join-Path $HOME '.ssh' 'known_hosts'
        $result | Should -Be $expected
    }
}
