BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelper.ps1')

    $script:Dir = New-TestDirectory
    $script:Config = Join-Path $script:Dir 'config'
    @'
# comment
Host web
    HostName web01.internal.example
    User deploy
    Port 2200
    IdentityFile ~/.ssh/id_web
    IdentityFile "%d/.ssh/id_backup"

Host *.lab !secret.lab
    User labuser

Host eq
    HostName=eq.example
    Port = 2022

Match host nothing
    User matched

Host *
    User fallback
    Port 22022
'@ | Set-Content -LiteralPath $script:Config
}

AfterAll {
    Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Get-SSHConfigHost' {
    It 'returns empty settings when the file does not exist' {
        $r = Get-SSHConfigHost -HostName 'web' -Path (Join-Path $script:Dir 'missing')
        $r.HostName | Should -BeNullOrEmpty
        $r.User | Should -BeNullOrEmpty
        $r.Port | Should -BeNullOrEmpty
        $r.IdentityFile.Count | Should -Be 0
    }

    It 'reads a Host block' {
        $r = Get-SSHConfigHost -HostName 'web' -Path $script:Config
        $r.HostName | Should -Be 'web01.internal.example'
        $r.User | Should -Be 'deploy'
        $r.Port | Should -Be 2200
    }

    It 'collects every IdentityFile and expands %d' {
        $r = Get-SSHConfigHost -HostName 'web' -Path $script:Config
        $r.IdentityFile.Count | Should -Be 2
        $r.IdentityFile[0] | Should -Be '~/.ssh/id_web'
        $r.IdentityFile[1] | Should -Be "$HOME/.ssh/id_backup"
    }

    It 'lets the first value win over later Host * defaults' {
        (Get-SSHConfigHost -HostName 'web' -Path $script:Config).User | Should -Be 'deploy'
    }

    It 'applies Host * to everything else' {
        $r = Get-SSHConfigHost -HostName 'unlisted.example' -Path $script:Config
        $r.User | Should -Be 'fallback'
        $r.Port | Should -Be 22022
        $r.HostName | Should -BeNullOrEmpty
    }

    It 'matches wildcard patterns and honours negation' {
        (Get-SSHConfigHost -HostName 'box1.lab' -Path $script:Config).User | Should -Be 'labuser'
        (Get-SSHConfigHost -HostName 'secret.lab' -Path $script:Config).User | Should -Be 'fallback'
    }

    It 'accepts Keyword=value syntax' {
        $r = Get-SSHConfigHost -HostName 'eq' -Path $script:Config
        $r.HostName | Should -Be 'eq.example'
        $r.Port | Should -Be 2022
    }

    It 'ignores Match blocks' {
        (Get-SSHConfigHost -HostName 'nothing' -Path $script:Config).User | Should -Be 'fallback'
    }

    It 'matches host names case-insensitively' {
        (Get-SSHConfigHost -HostName 'WEB' -Path $script:Config).User | Should -Be 'deploy'
    }
}

Describe 'Resolve-SSHHostName edge cases' {
    It 'rejects an out-of-range port' {
        { Resolve-SSHHostName -Target 'host:99999' } | Should -Throw '*port*'
        { Resolve-SSHHostName -Target 'host:0' } | Should -Throw '*port*'
    }

    It 'reports whether the target carried a port' {
        (Resolve-SSHHostName -Target 'host').HasPort | Should -BeFalse
        (Resolve-SSHHostName -Target 'host:22').HasPort | Should -BeTrue
    }

    It 'treats an unbracketed IPv6 address as a host' {
        $r = Resolve-SSHHostName -Target 'fe80::1'
        $r.ComputerName | Should -Be 'fe80::1'
        $r.Port | Should -Be 22
    }

    It 'splits the user on the last @' {
        $r = Resolve-SSHHostName -Target 'user@corp.example@host:2222'
        $r.UserName | Should -Be 'user@corp.example'
        $r.ComputerName | Should -Be 'host'
    }

    It 'rejects whitespace in the host name' {
        { Resolve-SSHHostName -Target 'bad host' } | Should -Throw
    }
}

Describe 'Resolve-SSHLocalPath' {
    It 'resolves relative paths against the PowerShell location' {
        Push-Location $script:Dir
        try {
            Resolve-SSHLocalPath -Path 'some/file' | Should -Be (Join-Path (Join-Path $script:Dir 'some') 'file')
        }
        finally { Pop-Location }
    }

    It 'expands ~' {
        Resolve-SSHLocalPath -Path '~/x' | Should -Be (Join-Path $HOME 'x')
    }

    It 'does not require the path to exist' {
        { Resolve-SSHLocalPath -Path (Join-Path $script:Dir 'does/not/exist') } | Should -Not -Throw
    }
}
