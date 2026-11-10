BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelper.ps1')
}

Describe 'Get-SSHPortForward' {
    BeforeEach {
        $script:SSHPortForwards.Clear()

        $fwd1 = [SSHPortForward]::new()
        $fwd1.ForwardId = 1
        $fwd1.SessionId = 1
        $fwd1.Type = 'Local'
        $fwd1.BoundPort = 8080
        $fwd1.IsStarted = $true
        $script:SSHPortForwards[1] = $fwd1

        $fwd2 = [SSHPortForward]::new()
        $fwd2.ForwardId = 2
        $fwd2.SessionId = 2
        $fwd2.Type = 'Dynamic'
        $fwd2.BoundPort = 1080
        $fwd2.IsStarted = $true
        $script:SSHPortForwards[2] = $fwd2

        $fwd3 = [SSHPortForward]::new()
        $fwd3.ForwardId = 3
        $fwd3.SessionId = 1
        $fwd3.Type = 'Remote'
        $fwd3.BoundPort = 9090
        $fwd3.IsStarted = $false
        $script:SSHPortForwards[3] = $fwd3
    }

    It 'returns all forwards when no parameters given' {
        $result = Get-SSHPortForward
        $result.Count | Should -Be 3
    }

    It 'returns forward by ID' {
        $result = Get-SSHPortForward -ForwardId 1
        $result.BoundPort | Should -Be 8080
    }

    It 'returns multiple forwards by ID' {
        $result = Get-SSHPortForward -ForwardId 1, 2
        $result.Count | Should -Be 2
    }

    It 'filters by session ID' {
        $result = Get-SSHPortForward -SessionId 1
        $result.Count | Should -Be 2
    }

    It 'writes error for non-existent forward ID' {
        { Get-SSHPortForward -ForwardId 99 -ErrorAction Stop } | Should -Throw '*not found*'
    }
}

Describe 'Remove-SSHPortForward' {
    BeforeEach {
        $script:SSHPortForwards.Clear()

        $fwd1 = [SSHPortForward]::new()
        $fwd1.ForwardId = 1
        $fwd1.SessionId = 1
        $fwd1.Type = 'Local'
        $fwd1.BoundPort = 8080
        $fwd1.IsStarted = $false
        $script:SSHPortForwards[1] = $fwd1
    }

    It 'removes a forward by ID' {
        Remove-SSHPortForward -ForwardId 1 -Confirm:$false
        $script:SSHPortForwards.Count | Should -Be 0
    }

    It 'writes error for non-existent forward' {
        { Remove-SSHPortForward -ForwardId 99 -Confirm:$false -ErrorAction Stop } | Should -Throw '*not found*'
    }

    It 'accepts objects from pipeline' {
        $fwd = $script:SSHPortForwards[1]
        $fwd | Remove-SSHPortForward -Confirm:$false
        $script:SSHPortForwards.Count | Should -Be 0
    }

    It 'supports WhatIf' {
        Remove-SSHPortForward -ForwardId 1 -WhatIf
        $script:SSHPortForwards.Count | Should -Be 1
    }
}
