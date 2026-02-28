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
    . (Join-Path $publicPath 'Remove-SSHSession.ps1')

    $script:SSHSessions = [System.Collections.Generic.Dictionary[int, SSHSessionInfo]]::new()
    $script:SSHPortForwards = [System.Collections.Generic.Dictionary[int, SSHPortForward]]::new()
    $script:NextSessionId = 1
    $script:NextForwardId = 1
}

Describe 'Remove-SSHSession' {
    BeforeEach {
        $script:SSHSessions.Clear()
        $script:SSHPortForwards.Clear()

        $mockClient = [PSCustomObject]@{ IsConnected = $true }
        $mockClient | Add-Member -MemberType ScriptMethod -Name Disconnect -Value { $this.IsConnected = $false }
        $mockClient | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }

        $s1 = [SSHSessionInfo]::new()
        $s1.SessionId = 1
        $s1.ComputerName = 'server01'
        $s1.UserName = 'admin'
        $s1.Connected = $true
        $s1.InternalSession = $mockClient
        $script:SSHSessions[1] = $s1
    }

    It 'removes a session by ID' {
        Remove-SSHSession -SessionId 1 -Confirm:$false
        $script:SSHSessions.Count | Should -Be 0
    }

    It 'writes error for non-existent session' {
        { Remove-SSHSession -SessionId 99 -ErrorAction Stop -Confirm:$false } | Should -Throw '*not found*'
    }

    It 'removes multiple sessions' {
        $mockClient2 = [PSCustomObject]@{ IsConnected = $true }
        $mockClient2 | Add-Member -MemberType ScriptMethod -Name Disconnect -Value { $this.IsConnected = $false }
        $mockClient2 | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }

        $s2 = [SSHSessionInfo]::new()
        $s2.SessionId = 2
        $s2.ComputerName = 'server02'
        $s2.UserName = 'root'
        $s2.Connected = $true
        $s2.InternalSession = $mockClient2
        $script:SSHSessions[2] = $s2

        Remove-SSHSession -SessionId 1, 2 -Confirm:$false
        $script:SSHSessions.Count | Should -Be 0
    }

    It 'accepts session objects from pipeline' {
        $session = $script:SSHSessions[1]
        $session | Remove-SSHSession -Confirm:$false
        $script:SSHSessions.Count | Should -Be 0
    }

    It 'cleans up associated port forwards' {
        $fwd = [SSHPortForward]::new()
        $fwd.ForwardId = 1
        $fwd.SessionId = 1
        $fwd.IsStarted = $false
        $script:SSHPortForwards[1] = $fwd

        Remove-SSHSession -SessionId 1 -Confirm:$false
        $script:SSHPortForwards.Count | Should -Be 0
    }

    It 'supports ShouldProcess (WhatIf)' {
        Remove-SSHSession -SessionId 1 -WhatIf
        $script:SSHSessions.Count | Should -Be 1  # Should not actually remove
    }
}
