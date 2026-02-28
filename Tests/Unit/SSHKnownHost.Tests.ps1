BeforeAll {
    $classPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Classes'
    . (Join-Path $classPath 'SSHHostKey.ps1')
    . (Join-Path $classPath 'SSHKnownHost.ps1')
    . (Join-Path $classPath 'SSHCommandResult.ps1')
    . (Join-Path $classPath 'SSHPortForward.ps1')
    . (Join-Path $classPath 'SSHSession.ps1')

    $privatePath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Private'
    . (Join-Path $privatePath 'Initialize-SSHSessionStore.ps1')
    . (Join-Path $privatePath 'Get-SSHKnownHostsPath.ps1')
    . (Join-Path $privatePath 'ConvertTo-SSHFingerprint.ps1')

    $publicPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Public'
    . (Join-Path $publicPath 'Get-SSHKnownHost.ps1')
    . (Join-Path $publicPath 'Add-SSHKnownHost.ps1')
    . (Join-Path $publicPath 'Remove-SSHKnownHost.ps1')
}

Describe 'Get-SSHKnownHost' {
    BeforeAll {
        $testDir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_test_$([guid]::NewGuid().ToString('N'))"
        New-Item -Path $testDir -ItemType Directory -Force | Out-Null

        # Create a test known_hosts file
        $testKnownHosts = Join-Path $testDir 'known_hosts'
        @(
            'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
            '# This is a comment'
            '[10.0.0.1]:2222 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7'
            'server1,server1.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY='
            ''
        ) | Set-Content -Path $testKnownHosts
    }

    AfterAll {
        Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'reads all entries from known_hosts file' {
        $results = Get-SSHKnownHost -Path $testKnownHosts
        $results.Count | Should -BeGreaterOrEqual 3
    }

    It 'skips comment lines' {
        $results = Get-SSHKnownHost -Path $testKnownHosts
        $results.HostName | Should -Not -Contain '# This is a comment'
    }

    It 'parses standard port entry' {
        $results = Get-SSHKnownHost -Path $testKnownHosts -HostName 'github.com'
        $results.Count | Should -Be 1
        $results[0].HostName | Should -Be 'github.com'
        $results[0].Port | Should -Be 22
        $results[0].KeyType | Should -Be 'ssh-ed25519'
    }

    It 'parses non-standard port entry' {
        $results = Get-SSHKnownHost -Path $testKnownHosts -HostName '10.0.0.1'
        $results.Count | Should -Be 1
        $results[0].Port | Should -Be 2222
        $results[0].KeyType | Should -Be 'ssh-rsa'
    }

    It 'expands comma-separated hosts' {
        $results = Get-SSHKnownHost -Path $testKnownHosts -HostName 'server1'
        $results.Count | Should -Be 1
        $results[0].HostName | Should -Be 'server1'
    }

    It 'includes source file and line number' {
        $results = Get-SSHKnownHost -Path $testKnownHosts
        $results[0].Source | Should -Be $testKnownHosts
        $results[0].LineNumber | Should -BeGreaterThan 0
    }

    It 'computes fingerprints' {
        $results = Get-SSHKnownHost -Path $testKnownHosts -HostName 'github.com'
        $results[0].Fingerprint | Should -BeLike 'SHA256:*'
    }

    It 'returns empty for non-existent file' {
        $result = Get-SSHKnownHost -Path '/tmp/nonexistent_known_hosts_file'
        $result | Should -BeNullOrEmpty
    }

    It 'filters by hostname with wildcards' {
        $results = Get-SSHKnownHost -Path $testKnownHosts -HostName 'server*'
        $results.Count | Should -BeGreaterOrEqual 1
    }
}

Describe 'Add-SSHKnownHost' {
    BeforeAll {
        $testDir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_test_add_$([guid]::NewGuid().ToString('N'))"
        New-Item -Path $testDir -ItemType Directory -Force | Out-Null
    }

    AfterAll {
        Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'adds an entry to known_hosts' {
        $testFile = Join-Path $testDir 'add_test'
        Add-SSHKnownHost -HostName 'newhost.example.com' -KeyType 'ssh-ed25519' -KeyData 'AAAA1234' -Path $testFile -Confirm:$false
        $content = Get-Content $testFile -Raw
        $content | Should -BeLike '*newhost.example.com ssh-ed25519 AAAA1234*'
    }

    It 'adds bracketed entry for non-standard port' {
        $testFile = Join-Path $testDir 'add_port_test'
        Add-SSHKnownHost -HostName '10.0.0.1' -Port 2222 -KeyType 'ssh-rsa' -KeyData 'BBBB5678' -Path $testFile -Confirm:$false
        $content = Get-Content $testFile -Raw
        $content | Should -BeLike '*[10.0.0.1]:2222 ssh-rsa BBBB5678*'
    }

    It 'accepts SSHHostKey from pipeline' {
        $testFile = Join-Path $testDir 'pipe_test'
        $hostKey = [SSHHostKey]::new()
        $hostKey.ComputerName = 'pipehost'
        $hostKey.Port = 22
        $hostKey.KeyType = 'ssh-ed25519'
        $hostKey.RawKey = [byte[]]@(65, 65, 65, 65)

        $hostKey | Add-SSHKnownHost -Path $testFile -Confirm:$false
        $content = Get-Content $testFile -Raw
        $content | Should -BeLike '*pipehost ssh-ed25519*'
    }

    It 'supports WhatIf' {
        $testFile = Join-Path $testDir 'whatif_test'
        Add-SSHKnownHost -HostName 'whatif.example.com' -KeyType 'ssh-rsa' -KeyData 'XXXX' -Path $testFile -WhatIf
        Test-Path $testFile | Should -BeFalse
    }
}

Describe 'Remove-SSHKnownHost' {
    BeforeAll {
        $testDir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_test_rm_$([guid]::NewGuid().ToString('N'))"
        New-Item -Path $testDir -ItemType Directory -Force | Out-Null
    }

    AfterAll {
        Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'removes a host entry' {
        $testFile = Join-Path $testDir 'rm_test'
        @(
            'keep.example.com ssh-ed25519 AAAA'
            'remove.example.com ssh-rsa BBBB'
            'also-keep.example.com ssh-ed25519 CCCC'
        ) | Set-Content -Path $testFile

        Remove-SSHKnownHost -HostName 'remove.example.com' -Path $testFile -Confirm:$false
        $lines = Get-Content $testFile
        $lines.Count | Should -Be 2
        $lines | Should -Not -Match 'remove\.example\.com'
    }

    It 'removes entry on non-standard port' {
        $testFile = Join-Path $testDir 'rm_port_test'
        @(
            'keep.example.com ssh-ed25519 AAAA'
            '[10.0.0.1]:2222 ssh-rsa BBBB'
        ) | Set-Content -Path $testFile

        Remove-SSHKnownHost -HostName '10.0.0.1' -Port 2222 -Path $testFile -Confirm:$false
        $lines = Get-Content $testFile
        $lines.Count | Should -Be 1
    }

    It 'handles non-existent file gracefully' {
        Remove-SSHKnownHost -HostName 'test' -Path '/tmp/nonexistent_file_12345' -Confirm:$false 3>$null
        # Should not throw, just warn
    }

    It 'removes multiple hosts' {
        $testFile = Join-Path $testDir 'rm_multi_test'
        @(
            'host1 ssh-ed25519 AAAA'
            'host2 ssh-rsa BBBB'
            'host3 ssh-ed25519 CCCC'
        ) | Set-Content -Path $testFile

        Remove-SSHKnownHost -HostName 'host1', 'host3' -Path $testFile -Confirm:$false
        $lines = Get-Content $testFile
        $lines.Count | Should -Be 1
        $lines[0] | Should -BeLike '*host2*'
    }

    It 'supports WhatIf' {
        $testFile = Join-Path $testDir 'rm_whatif_test'
        @(
            'host1 ssh-ed25519 AAAA'
        ) | Set-Content -Path $testFile

        Remove-SSHKnownHost -HostName 'host1' -Path $testFile -WhatIf
        $lines = Get-Content $testFile
        $lines.Count | Should -Be 1  # Should not actually remove
    }
}
