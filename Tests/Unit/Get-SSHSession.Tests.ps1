BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelper.ps1')
}

Describe 'Get-SSHSession' {
    BeforeEach {
        $script:SSHSessions.Clear()

        # Add test sessions
        $s1 = [SSHSessionInfo]::new()
        $s1.SessionId = 1
        $s1.ComputerName = 'web01'
        $s1.UserName = 'admin'
        $s1.Connected = $true
        $s1.InternalSession = [PSCustomObject]@{ IsConnected = $true }
        $script:SSHSessions[1] = $s1

        $s2 = [SSHSessionInfo]::new()
        $s2.SessionId = 2
        $s2.ComputerName = 'db01'
        $s2.UserName = 'root'
        $s2.Connected = $false
        $s2.InternalSession = [PSCustomObject]@{ IsConnected = $false }
        $script:SSHSessions[2] = $s2

        $s3 = [SSHSessionInfo]::new()
        $s3.SessionId = 3
        $s3.ComputerName = 'web02'
        $s3.UserName = 'deploy'
        $s3.Connected = $true
        $s3.InternalSession = [PSCustomObject]@{ IsConnected = $true }
        $script:SSHSessions[3] = $s3
    }

    It 'returns all sessions when no parameters given' {
        $result = Get-SSHSession
        $result.Count | Should -Be 3
    }

    It 'returns specific session by ID' {
        $result = Get-SSHSession -SessionId 1
        $result.ComputerName | Should -Be 'web01'
    }

    It 'returns multiple sessions by ID' {
        $result = Get-SSHSession -SessionId 1, 3
        $result.Count | Should -Be 2
        $result.ComputerName | Should -Contain 'web01'
        $result.ComputerName | Should -Contain 'web02'
    }

    It 'writes error for non-existent session ID' {
        { Get-SSHSession -SessionId 99 -ErrorAction Stop } | Should -Throw '*not found*'
    }

    It 'filters by computer name with wildcard' {
        $result = Get-SSHSession -ComputerName 'web*'
        $result.Count | Should -Be 2
    }

    It 'returns no results for non-matching name' {
        $result = Get-SSHSession -ComputerName 'nonexistent'
        $result | Should -BeNullOrEmpty
    }

    It 'filters active sessions only' {
        $result = Get-SSHSession -Active
        $result.Count | Should -Be 2
        $result.ComputerName | Should -Not -Contain 'db01'
    }

    It 'combines name filter with active flag' {
        $result = Get-SSHSession -ComputerName 'db*' -Active
        $result | Should -BeNullOrEmpty
    }

    It 'accepts SessionId from pipeline' {
        $result = 1, 2 | Get-SSHSession
        $result.Count | Should -Be 2
    }
}
