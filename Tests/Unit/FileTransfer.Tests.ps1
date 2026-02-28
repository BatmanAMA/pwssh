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
    . (Join-Path $publicPath 'Send-SCPFile.ps1')
    . (Join-Path $publicPath 'Receive-SCPFile.ps1')
    . (Join-Path $publicPath 'Send-SFTPFile.ps1')
    . (Join-Path $publicPath 'Receive-SFTPFile.ps1')
    . (Join-Path $publicPath 'Get-SFTPChildItem.ps1')

    $script:SSHSessions = [System.Collections.Generic.Dictionary[int, SSHSessionInfo]]::new()
    $script:SSHPortForwards = [System.Collections.Generic.Dictionary[int, SSHPortForward]]::new()
    $script:NextSessionId = 1
    $script:NextForwardId = 1
}

Describe 'Send-SCPFile' {
    Context 'Parameter validation' {
        It 'requires SessionId or Session' {
            $cmd = Get-Command Send-SCPFile
            $cmd.ParameterSets.Count | Should -BeGreaterOrEqual 2
        }

        It 'has LocalPath aliases' {
            $cmd = Get-Command Send-SCPFile
            $aliases = $cmd.Parameters['LocalPath'].Aliases
            $aliases | Should -Contain 'Source'
            $aliases | Should -Contain 'Path'
        }

        It 'has RemotePath alias' {
            $cmd = Get-Command Send-SCPFile
            $aliases = $cmd.Parameters['RemotePath'].Aliases
            $aliases | Should -Contain 'Destination'
        }

        It 'has Recurse switch' {
            $cmd = Get-Command Send-SCPFile
            $cmd.Parameters['Recurse'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Error handling' {
        It 'writes error for non-existent session' {
            { Send-SCPFile -SessionId 99 -LocalPath '/tmp/test' -RemotePath '/tmp/test' -ErrorAction Stop } | Should -Throw '*not found*'
        }

        It 'writes error for disconnected session' {
            $s = [SSHSessionInfo]::new()
            $s.SessionId = 1
            $s.Connected = $false
            $s.InternalSession = [PSCustomObject]@{ IsConnected = $false }
            $script:SSHSessions[1] = $s

            { Send-SCPFile -SessionId 1 -LocalPath '/tmp/test' -RemotePath '/tmp/test' -ErrorAction Stop } | Should -Throw '*not connected*'
            $script:SSHSessions.Clear()
        }
    }
}

Describe 'Receive-SCPFile' {
    Context 'Parameter validation' {
        It 'has RemotePath aliases' {
            $cmd = Get-Command Receive-SCPFile
            $aliases = $cmd.Parameters['RemotePath'].Aliases
            $aliases | Should -Contain 'Source'
        }

        It 'has LocalPath aliases' {
            $cmd = Get-Command Receive-SCPFile
            $aliases = $cmd.Parameters['LocalPath'].Aliases
            $aliases | Should -Contain 'Destination'
            $aliases | Should -Contain 'Path'
        }

        It 'has Recurse switch' {
            $cmd = Get-Command Receive-SCPFile
            $cmd.Parameters['Recurse'].SwitchParameter | Should -BeTrue
        }
    }
}

Describe 'Send-SFTPFile' {
    Context 'Parameter validation' {
        It 'has Overwrite switch' {
            $cmd = Get-Command Send-SFTPFile
            $cmd.Parameters['Overwrite'].SwitchParameter | Should -BeTrue
        }

        It 'has both ById and BySession parameter sets' {
            $cmd = Get-Command Send-SFTPFile
            $cmd.ParameterSets.Name | Should -Contain 'ById'
            $cmd.ParameterSets.Name | Should -Contain 'BySession'
        }
    }
}

Describe 'Receive-SFTPFile' {
    Context 'Parameter validation' {
        It 'has Overwrite switch' {
            $cmd = Get-Command Receive-SFTPFile
            $cmd.Parameters['Overwrite'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Error handling' {
        It 'writes error for non-existent session' {
            { Receive-SFTPFile -SessionId 99 -RemotePath '/tmp/test' -LocalPath '/tmp/local' -ErrorAction Stop } | Should -Throw '*not found*'
        }
    }
}

Describe 'Get-SFTPChildItem' {
    Context 'Parameter validation' {
        It 'has Recurse switch' {
            $cmd = Get-Command Get-SFTPChildItem
            $cmd.Parameters['Recurse'].SwitchParameter | Should -BeTrue
        }

        It 'defaults Path to current directory' {
            $cmd = Get-Command Get-SFTPChildItem
            $cmd.Parameters['Path'] | Should -Not -BeNullOrEmpty
        }
    }
}
