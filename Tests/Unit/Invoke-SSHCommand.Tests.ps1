BeforeAll {
    $classPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Classes'
    . (Join-Path $classPath 'SSHHostKey.ps1')
    . (Join-Path $classPath 'SSHKnownHost.ps1')
    . (Join-Path $classPath 'SSHCommandResult.ps1')
    . (Join-Path $classPath 'SSHPortForward.ps1')
    . (Join-Path $classPath 'SSHSession.ps1')

    $privatePath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Private'
    . (Join-Path $privatePath 'Initialize-SSHSessionStore.ps1')

    $publicPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Public'
    . (Join-Path $publicPath 'Invoke-SSHCommand.ps1')

    $script:SSHSessions = [System.Collections.Generic.Dictionary[int, SSHSessionInfo]]::new()
    $script:SSHPortForwards = [System.Collections.Generic.Dictionary[int, SSHPortForward]]::new()
    $script:NextSessionId = 1
    $script:NextForwardId = 1
}

Describe 'Invoke-SSHCommand' {
    BeforeEach {
        $script:SSHSessions.Clear()

        # Build a mock SshClient that returns a mock SshCommand
        $mockCmd = [PSCustomObject]@{
            CommandTimeout = [timespan]::Zero
            ExitStatus     = 0
            Result         = 'mock output'
            Error          = ''
        }
        $mockCmd | Add-Member -MemberType ScriptMethod -Name Execute -Value { }
        $mockCmd | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }

        $mockClient = [PSCustomObject]@{ IsConnected = $true }
        $mockClient | Add-Member -MemberType ScriptMethod -Name CreateCommand -Value { param($cmd) $script:lastMockCmd = $cmd; $mockCmd } -Force

        $s1 = [SSHSessionInfo]::new()
        $s1.SessionId = 1
        $s1.ComputerName = 'server01'
        $s1.UserName = 'admin'
        $s1.Connected = $true
        $s1.InternalSession = $mockClient
        $script:SSHSessions[1] = $s1
    }

    It 'executes a command and returns SSHCommandResult' {
        $result = Invoke-SSHCommand -SessionId 1 -Command 'whoami'
        $result | Should -BeOfType [SSHCommandResult]
        $result.Output | Should -Be 'mock output'
        $result.ExitCode | Should -Be 0
    }

    It 'sets session and computer name on result' {
        $result = Invoke-SSHCommand -SessionId 1 -Command 'test'
        $result.SessionId | Should -Be 1
        $result.ComputerName | Should -Be 'server01'
    }

    It 'stores the command string' {
        $result = Invoke-SSHCommand -SessionId 1 -Command 'ls -la /tmp'
        $result.Command | Should -Be 'ls -la /tmp'
    }

    It 'records start and end time' {
        $result = Invoke-SSHCommand -SessionId 1 -Command 'date'
        $result.StartTime | Should -Not -Be ([datetime]::MinValue)
        $result.EndTime | Should -BeGreaterOrEqual $result.StartTime
    }

    It 'calculates duration' {
        $result = Invoke-SSHCommand -SessionId 1 -Command 'sleep 0'
        $result.Duration | Should -BeOfType [timespan]
    }

    It 'writes error for non-existent session' {
        { Invoke-SSHCommand -SessionId 99 -Command 'test' -ErrorAction Stop } | Should -Throw '*not found*'
    }

    It 'writes error for disconnected session' {
        $script:SSHSessions[1].Connected = $false
        { Invoke-SSHCommand -SessionId 1 -Command 'test' -ErrorAction Stop } | Should -Throw '*not connected*'
    }

    It 'executes across multiple sessions' {
        $mockCmd2 = [PSCustomObject]@{
            CommandTimeout = [timespan]::Zero
            ExitStatus     = 0
            Result         = 'output from server02'
            Error          = ''
        }
        $mockCmd2 | Add-Member -MemberType ScriptMethod -Name Execute -Value { }
        $mockCmd2 | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }

        $mockClient2 = [PSCustomObject]@{ IsConnected = $true }
        $mockClient2 | Add-Member -MemberType ScriptMethod -Name CreateCommand -Value { param($cmd) $mockCmd2 }

        $s2 = [SSHSessionInfo]::new()
        $s2.SessionId = 2
        $s2.ComputerName = 'server02'
        $s2.UserName = 'root'
        $s2.Connected = $true
        $s2.InternalSession = $mockClient2
        $script:SSHSessions[2] = $s2

        $results = Invoke-SSHCommand -SessionId 1, 2 -Command 'hostname'
        $results.Count | Should -Be 2
    }

    It 'handles command that returns non-zero exit code' {
        $failCmd = [PSCustomObject]@{
            CommandTimeout = [timespan]::Zero
            ExitStatus     = 1
            Result         = ''
            Error          = 'command not found'
        }
        $failCmd | Add-Member -MemberType ScriptMethod -Name Execute -Value { }
        $failCmd | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }

        $mockClient = $script:SSHSessions[1].InternalSession
        $mockClient | Add-Member -MemberType ScriptMethod -Name CreateCommand -Value { param($cmd) $failCmd } -Force

        $result = Invoke-SSHCommand -SessionId 1 -Command 'badcommand'
        $result.ExitCode | Should -Be 1
        $result.Error | Should -Be 'command not found'
    }
}
