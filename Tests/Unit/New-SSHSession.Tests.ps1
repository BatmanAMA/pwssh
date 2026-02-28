BeforeAll {
    $classPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Classes'
    . (Join-Path $classPath 'SSHHostKey.ps1')
    . (Join-Path $classPath 'SSHKnownHost.ps1')
    . (Join-Path $classPath 'SSHCommandResult.ps1')
    . (Join-Path $classPath 'SSHPortForward.ps1')
    . (Join-Path $classPath 'SSHSession.ps1')

    $privatePath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Private'
    . (Join-Path $privatePath 'Initialize-SSHSessionStore.ps1')
    . (Join-Path $privatePath 'Resolve-SSHHostName.ps1')
    . (Join-Path $privatePath 'Get-SSHAuthMethod.ps1')
    . (Join-Path $privatePath 'ConvertTo-SSHFingerprint.ps1')

    $publicPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Public'
    . (Join-Path $publicPath 'New-SSHSession.ps1')

    $script:SSHSessions = [System.Collections.Generic.Dictionary[int, SSHSessionInfo]]::new()
    $script:SSHPortForwards = [System.Collections.Generic.Dictionary[int, SSHPortForward]]::new()
    $script:NextSessionId = 1
    $script:NextForwardId = 1
}

Describe 'New-SSHSession' {
    Context 'Parameter validation' {
        It 'requires ComputerName' {
            { New-SSHSession -ComputerName $null } | Should -Throw
        }

        It 'accepts Port in valid range' {
            $cmd = Get-Command New-SSHSession
            $portParam = $cmd.Parameters['Port']
            $portParam | Should -Not -BeNullOrEmpty
            $validateRange = $portParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $validateRange | Should -Not -BeNullOrEmpty
        }

        It 'accepts ConnectionTimeout in valid range' {
            $cmd = Get-Command New-SSHSession
            $param = $cmd.Parameters['ConnectionTimeout']
            $validateRange = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateRangeAttribute] }
            $validateRange | Should -Not -BeNullOrEmpty
        }

        It 'has KeyFile parameter set' {
            $cmd = Get-Command New-SSHSession
            $cmd.ParameterSets.Name | Should -Contain 'KeyFile'
        }

        It 'has Credential parameter set' {
            $cmd = Get-Command New-SSHSession
            $cmd.ParameterSets.Name | Should -Contain 'Credential'
        }

        It 'has all expected aliases' {
            $cmd = Get-Command New-SSHSession
            $aliases = $cmd.Parameters['ComputerName'].Aliases
            $aliases | Should -Contain 'HostName'
            $aliases | Should -Contain 'Host'
            $aliases | Should -Contain 'Server'
            $aliases | Should -Contain 'Target'
        }

        It 'has KeyFile aliases' {
            $cmd = Get-Command New-SSHSession
            $aliases = $cmd.Parameters['KeyFile'].Aliases
            $aliases | Should -Contain 'Identity'
            $aliases | Should -Contain 'IdentityFile'
        }

        It 'outputs SSHSessionInfo type' {
            $cmd = Get-Command New-SSHSession
            $outputType = $cmd.OutputType
            $outputType.Type.Name | Should -Contain 'SSHSessionInfo'
        }

        It 'accepts pipeline input for ComputerName' {
            $cmd = Get-Command New-SSHSession
            $param = $cmd.Parameters['ComputerName']
            $pipelineAttr = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.ValueFromPipeline }
            $pipelineAttr | Should -Not -BeNullOrEmpty
        }

        It 'has AcceptKey switch' {
            $cmd = Get-Command New-SSHSession
            $cmd.Parameters['AcceptKey'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Connection logic (mocked)' {
        It 'writes error when no auth methods available and no default keys exist' {
            Mock Get-SSHAuthMethod { return @() }
            Mock Test-Path { return $false } -ParameterFilter { $Path -like '*/.ssh/*' }

            { New-SSHSession -ComputerName 'unreachable.test' -ErrorAction Stop } | Should -Throw
        }
    }
}
