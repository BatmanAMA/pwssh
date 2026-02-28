BeforeAll {
    # Load crypto engine
    $initCryptoPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Private' 'Initialize-SSHCrypto.ps1'
    . $initCryptoPath
    Initialize-SSHCrypto

    $publicPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Public'
    . (Join-Path $publicPath 'New-SSHKeyPair.ps1')
}

Describe 'New-SSHKeyPair' {
    Context 'Parameter validation' {
        It 'has KeyType parameter with valid set' {
            $cmd = Get-Command New-SSHKeyPair
            $param = $cmd.Parameters['KeyType']
            $validateSet = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validateSet.ValidValues | Should -Contain 'Ed25519'
            $validateSet.ValidValues | Should -Contain 'RSA'
            $validateSet.ValidValues | Should -Contain 'ECDSA'
        }

        It 'has Force switch' {
            $cmd = Get-Command New-SSHKeyPair
            $cmd.Parameters['Force'].SwitchParameter | Should -BeTrue
        }

        It 'has Passphrase parameter accepting SecureString' {
            $cmd = Get-Command New-SSHKeyPair
            $cmd.Parameters['Passphrase'].ParameterType | Should -Be ([securestring])
        }

        It 'supports ShouldProcess' {
            $cmd = Get-Command New-SSHKeyPair
            $cmdletBinding = $cmd.ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
            $cmdletBinding.SupportsShouldProcess | Should -BeTrue
        }
    }

    Context 'Key generation (internal crypto — no ssh-keygen dependency)' {
        BeforeAll {
            $testDir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_keygen_$([guid]::NewGuid().ToString('N'))"
            New-Item -Path $testDir -ItemType Directory -Force | Out-Null
        }

        AfterAll {
            Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'generates an Ed25519 key pair' {
            $keyPath = Join-Path $testDir 'test_ed25519'
            $result = New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'ed25519-test'
            $result.PrivateKeyPath | Should -Be $keyPath
            $result.PublicKeyPath | Should -Be "$keyPath.pub"
            $result.KeyType | Should -Be 'Ed25519'
            $result.Fingerprint | Should -BeLike 'SHA256:*'
            $result.Encrypted | Should -BeFalse
            Test-Path $keyPath | Should -BeTrue
            Test-Path "$keyPath.pub" | Should -BeTrue
        }

        It 'generates an RSA key pair' {
            $keyPath = Join-Path $testDir 'test_rsa'
            $result = New-SSHKeyPair -Path $keyPath -KeyType RSA -KeySize 2048
            $result.KeyType | Should -Be 'RSA'
            Test-Path $keyPath | Should -BeTrue
            Test-Path "$keyPath.pub" | Should -BeTrue
        }

        It 'generates an ECDSA key pair' {
            $keyPath = Join-Path $testDir 'test_ecdsa'
            $result = New-SSHKeyPair -Path $keyPath -KeyType ECDSA
            $result.KeyType | Should -Be 'ECDSA'
            Test-Path $keyPath | Should -BeTrue
        }

        It 'refuses to overwrite without -Force' {
            $keyPath = Join-Path $testDir 'test_overwrite'
            [System.IO.File]::WriteAllText($keyPath, 'existing key')
            { New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -ErrorAction Stop } | Should -Throw '*already exists*'
        }

        It 'overwrites with -Force' {
            $keyPath = Join-Path $testDir 'test_force'
            [System.IO.File]::WriteAllText($keyPath, 'old key')
            $result = New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Force
            $result.KeyType | Should -Be 'Ed25519'
        }

        It 'includes comment in result' {
            $keyPath = Join-Path $testDir 'test_comment'
            $result = New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'test-key'
            $result.Comment | Should -Be 'test-key'
        }

        It 'supports WhatIf' {
            $keyPath = Join-Path $testDir 'test_whatif'
            New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -WhatIf
            Test-Path $keyPath | Should -BeFalse
        }

        It 'writes valid OpenSSH format private key' {
            $keyPath = Join-Path $testDir 'test_format'
            New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'fmt'
            $content = Get-Content $keyPath -Raw
            $content | Should -BeLike '*-----BEGIN OPENSSH PRIVATE KEY-----*'
        }

        It 'generates encrypted key with -Passphrase' {
            $keyPath = Join-Path $testDir 'test_passphrase'
            $pass = ConvertTo-SecureString 'hunter2' -AsPlainText -Force
            $result = New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Passphrase $pass
            $result.Encrypted | Should -BeTrue
        }
    }
}
