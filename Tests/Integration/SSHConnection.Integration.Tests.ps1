<#
.SYNOPSIS
    Integration tests for pwssh module — require a real SSH server.
.DESCRIPTION
    These tests connect to an actual SSH server. Configure the environment
    variables below before running:

    $env:PWSSH_TEST_HOST      - SSH server hostname (default: localhost)
    $env:PWSSH_TEST_PORT      - SSH port (default: 22)
    $env:PWSSH_TEST_USER      - Username
    $env:PWSSH_TEST_PASSWORD  - Password (for password auth tests)
    $env:PWSSH_TEST_KEYFILE   - Path to private key (for key auth tests)

    Run with: Invoke-Pester -Path ./Tests/Integration -Tag 'Integration'
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'pwssh.psd1'

    # Skip all integration tests if no test host configured
    $script:TestHost     = if ($env:PWSSH_TEST_HOST) { $env:PWSSH_TEST_HOST } else { 'localhost' }
    $script:TestPort     = [int](if ($env:PWSSH_TEST_PORT) { $env:PWSSH_TEST_PORT } else { 22 })
    $script:TestUser     = $env:PWSSH_TEST_USER
    $script:TestPassword = $env:PWSSH_TEST_PASSWORD
    $script:TestKeyFile  = $env:PWSSH_TEST_KEYFILE
    $script:CanRun       = -not [string]::IsNullOrEmpty($script:TestUser)

    if ($script:CanRun) {
        Import-Module $modulePath -Force
    }
}

Describe 'SSH Connection Integration' -Tag 'Integration' -Skip:(-not $script:CanRun) {

    Context 'Password authentication' -Skip:([string]::IsNullOrEmpty($script:TestPassword)) {
        It 'connects with password credential' {
            $secPass = ConvertTo-SecureString $script:TestPassword -AsPlainText -Force
            $cred = [pscredential]::new($script:TestUser, $secPass)

            $session = New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -Credential $cred -AcceptKey
            $session | Should -Not -BeNullOrEmpty
            $session.Connected | Should -BeTrue
            $session.UserName | Should -Be $script:TestUser

            Remove-SSHSession -SessionId $session.SessionId -Confirm:$false
        }
    }

    Context 'Key authentication' -Skip:([string]::IsNullOrEmpty($script:TestKeyFile)) {
        It 'connects with key file' {
            $session = New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -UserName $script:TestUser -KeyFile $script:TestKeyFile -AcceptKey
            $session | Should -Not -BeNullOrEmpty
            $session.Connected | Should -BeTrue

            Remove-SSHSession -SessionId $session.SessionId -Confirm:$false
        }
    }

    Context 'Command execution' -Skip:([string]::IsNullOrEmpty($script:TestPassword)) {
        BeforeAll {
            $secPass = ConvertTo-SecureString $script:TestPassword -AsPlainText -Force
            $cred = [pscredential]::new($script:TestUser, $secPass)
            $script:IntSession = New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -Credential $cred -AcceptKey
        }

        AfterAll {
            if ($script:IntSession) {
                Remove-SSHSession -SessionId $script:IntSession.SessionId -Confirm:$false -ErrorAction SilentlyContinue
            }
        }

        It 'executes a simple command' {
            $result = Invoke-SSHCommand -SessionId $script:IntSession.SessionId -Command 'echo hello'
            $result.ExitCode | Should -Be 0
            $result.Output.Trim() | Should -Be 'hello'
        }

        It 'returns non-zero exit code for failing command' {
            $result = Invoke-SSHCommand -SessionId $script:IntSession.SessionId -Command 'exit 42'
            $result.ExitCode | Should -Be 42
        }

        It 'captures stderr' {
            $result = Invoke-SSHCommand -SessionId $script:IntSession.SessionId -Command 'echo errtest >&2'
            $result.Error | Should -BeLike '*errtest*'
        }

        It 'runs command across multiple sessions' {
            $s2 = New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -Credential $cred -AcceptKey
            $results = Invoke-SSHCommand -SessionId $script:IntSession.SessionId, $s2.SessionId -Command 'hostname'
            $results.Count | Should -Be 2
            Remove-SSHSession -SessionId $s2.SessionId -Confirm:$false
        }
    }

    Context 'SCP file transfer' -Skip:([string]::IsNullOrEmpty($script:TestPassword)) {
        BeforeAll {
            $secPass = ConvertTo-SecureString $script:TestPassword -AsPlainText -Force
            $cred = [pscredential]::new($script:TestUser, $secPass)
            $script:ScpSession = New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -Credential $cred -AcceptKey
            $script:TestContent = "pwssh test file $(Get-Date -Format o)"
        }

        AfterAll {
            if ($script:ScpSession) {
                Invoke-SSHCommand -SessionId $script:ScpSession.SessionId -Command 'rm -f /tmp/pwssh_test_upload.txt' -ErrorAction SilentlyContinue
                Remove-SSHSession -SessionId $script:ScpSession.SessionId -Confirm:$false -ErrorAction SilentlyContinue
            }
        }

        It 'uploads a file via SCP' {
            $localFile = Join-Path ([System.IO.Path]::GetTempPath()) 'pwssh_scp_test.txt'
            $script:TestContent | Set-Content -Path $localFile
            { Send-SCPFile -SessionId $script:ScpSession.SessionId -LocalPath $localFile -RemotePath '/tmp/pwssh_test_upload.txt' } | Should -Not -Throw
            Remove-Item $localFile -Force
        }

        It 'downloads a file via SCP' {
            $downloadPath = Join-Path ([System.IO.Path]::GetTempPath()) 'pwssh_scp_download.txt'
            { Receive-SCPFile -SessionId $script:ScpSession.SessionId -RemotePath '/tmp/pwssh_test_upload.txt' -LocalPath $downloadPath } | Should -Not -Throw
            $content = Get-Content $downloadPath -Raw
            $content.Trim() | Should -Be $script:TestContent
            Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Port forwarding' -Skip:([string]::IsNullOrEmpty($script:TestPassword)) {
        BeforeAll {
            $secPass = ConvertTo-SecureString $script:TestPassword -AsPlainText -Force
            $cred = [pscredential]::new($script:TestUser, $secPass)
            $script:FwdSession = New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -Credential $cred -AcceptKey
        }

        AfterAll {
            if ($script:FwdSession) {
                Get-SSHPortForward -SessionId $script:FwdSession.SessionId | Remove-SSHPortForward -Confirm:$false -ErrorAction SilentlyContinue
                Remove-SSHSession -SessionId $script:FwdSession.SessionId -Confirm:$false -ErrorAction SilentlyContinue
            }
        }

        It 'creates a local port forward' {
            $fwd = New-SSHPortForward -SessionId $script:FwdSession.SessionId -Type Local -BoundPort 18080 -RemoteHost localhost -RemotePort 80
            $fwd | Should -Not -BeNullOrEmpty
            $fwd.IsStarted | Should -BeTrue
            Remove-SSHPortForward -ForwardId $fwd.ForwardId -Confirm:$false
        }

        It 'creates a dynamic (SOCKS) forward' {
            $fwd = New-SSHPortForward -SessionId $script:FwdSession.SessionId -Type Dynamic -BoundPort 11080
            $fwd | Should -Not -BeNullOrEmpty
            $fwd.Type | Should -Be 'Dynamic'
            Remove-SSHPortForward -ForwardId $fwd.ForwardId -Confirm:$false
        }
    }

    Context 'Host key retrieval' {
        It 'retrieves host key from test server' -Skip:(-not $script:CanRun) {
            $key = Get-SSHHostKey -ComputerName $script:TestHost -Port $script:TestPort
            $key | Should -Not -BeNullOrEmpty
            $key.KeyType | Should -Not -BeNullOrEmpty
            $key.Fingerprint | Should -BeLike 'SHA256:*'
        }
    }

    Context 'Session management' -Skip:([string]::IsNullOrEmpty($script:TestPassword)) {
        It 'lists sessions and filters active ones' {
            $secPass = ConvertTo-SecureString $script:TestPassword -AsPlainText -Force
            $cred = [pscredential]::new($script:TestUser, $secPass)

            $s1 = New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -Credential $cred -AcceptKey
            $s2 = New-SSHSession -ComputerName $script:TestHost -Port $script:TestPort -Credential $cred -AcceptKey

            $all = Get-SSHSession
            $all.Count | Should -BeGreaterOrEqual 2

            $active = Get-SSHSession -Active
            $active.Count | Should -BeGreaterOrEqual 2

            Remove-SSHSession -SessionId $s1.SessionId, $s2.SessionId -Confirm:$false
        }
    }
}
