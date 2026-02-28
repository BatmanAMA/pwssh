BeforeAll {
    # Load crypto engine
    $initCryptoPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Private' 'Initialize-SSHCrypto.ps1'
    . $initCryptoPath
    Initialize-SSHCrypto

    # Load cmdlets
    $publicPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Public'
    . (Join-Path $publicPath 'New-SSHKeyPair.ps1')
    . (Join-Path $publicPath 'ConvertTo-SSHPublicKey.ps1')
    . (Join-Path $publicPath 'Get-SSHKeyFingerprint.ps1')
    . (Join-Path $publicPath 'Test-SSHKeyFile.ps1')

    # Temp directory for test keys
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_test_$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    New-Item -Path $script:TempDir -ItemType Directory -Force | Out-Null
}

AfterAll {
    if ($script:TempDir -and (Test-Path $script:TempDir)) {
        Remove-Item $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'New-SSHKeyPair (internal crypto)' {
    Context 'Ed25519 key generation' {
        It 'generates an Ed25519 key pair' {
            $keyPath = Join-Path $script:TempDir 'test_ed25519'
            $result = New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'test@pester'

            $result | Should -Not -BeNullOrEmpty
            $result.KeyType | Should -Be 'Ed25519'
            $result.Comment | Should -Be 'test@pester'
            $result.Fingerprint | Should -BeLike 'SHA256:*'
            $result.Encrypted | Should -BeFalse
            Test-Path $keyPath | Should -BeTrue
            Test-Path "$keyPath.pub" | Should -BeTrue
        }

        It 'private key has correct OpenSSH format' {
            $keyPath = Join-Path $script:TempDir 'test_ed25519_format'
            New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'fmt-test'
            $content = Get-Content $keyPath -Raw
            $content | Should -BeLike '*-----BEGIN OPENSSH PRIVATE KEY-----*'
            $content | Should -BeLike '*-----END OPENSSH PRIVATE KEY-----*'
        }

        It 'public key has correct format' {
            $keyPath = Join-Path $script:TempDir 'test_ed25519_pub'
            New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'pub-test'
            $pubContent = Get-Content "$keyPath.pub" -Raw
            $pubContent.Trim() | Should -Match '^ssh-ed25519 AAAA\S+ pub-test$'
        }
    }

    Context 'RSA key generation' {
        It 'generates an RSA-2048 key pair' {
            $keyPath = Join-Path $script:TempDir 'test_rsa'
            $result = New-SSHKeyPair -Path $keyPath -KeyType RSA -KeySize 2048 -Comment 'rsa@pester'

            $result.KeyType | Should -Be 'RSA'
            Test-Path $keyPath | Should -BeTrue
            Test-Path "$keyPath.pub" | Should -BeTrue
        }

        It 'public key starts with ssh-rsa' {
            $keyPath = Join-Path $script:TempDir 'test_rsa_pub'
            New-SSHKeyPair -Path $keyPath -KeyType RSA -KeySize 2048 -Comment 'rsa-pub'
            $pubContent = Get-Content "$keyPath.pub" -Raw
            $pubContent.Trim() | Should -BeLike 'ssh-rsa AAAA*'
        }
    }

    Context 'ECDSA key generation' {
        It 'generates an ECDSA-256 key pair' {
            $keyPath = Join-Path $script:TempDir 'test_ecdsa'
            $result = New-SSHKeyPair -Path $keyPath -KeyType ECDSA -KeySize 256 -Comment 'ecdsa@pester'

            $result.KeyType | Should -Be 'ECDSA'
            Test-Path $keyPath | Should -BeTrue
        }
    }

    Context 'Passphrase protection' {
        It 'generates an encrypted key with passphrase' {
            $keyPath = Join-Path $script:TempDir 'test_encrypted'
            $pass = ConvertTo-SecureString 'testpass123' -AsPlainText -Force
            $result = New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Passphrase $pass -Comment 'enc-test'

            $result.Encrypted | Should -BeTrue
            # Verify the key file mentions encryption
            $content = Get-Content $keyPath -Raw
            $content | Should -BeLike '*BEGIN OPENSSH PRIVATE KEY*'
        }
    }

    Context 'Overwrite protection' {
        It 'refuses to overwrite without -Force' {
            $keyPath = Join-Path $script:TempDir 'test_overwrite'
            New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'first'
            { New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'second' -ErrorAction Stop } |
                Should -Throw '*already exists*'
        }

        It 'overwrites with -Force' {
            $keyPath = Join-Path $script:TempDir 'test_force'
            New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'first'
            $result = New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'forced' -Force
            $result.Comment | Should -Be 'forced'
        }
    }

    Context 'WhatIf support' {
        It 'does not create files with -WhatIf' {
            $keyPath = Join-Path $script:TempDir 'test_whatif'
            New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -WhatIf
            Test-Path $keyPath | Should -BeFalse
        }
    }
}

Describe 'ConvertTo-SSHPublicKey' {
    BeforeAll {
        $script:ConvertKeyPath = Join-Path $script:TempDir 'convert_ed25519'
        New-SSHKeyPair -Path $script:ConvertKeyPath -KeyType Ed25519 -Comment 'convert-test'
    }

    It 'extracts public key from private key file' {
        $result = ConvertTo-SSHPublicKey -Path $script:ConvertKeyPath
        $result | Should -Not -BeNullOrEmpty
        $result.KeyType | Should -Be 'ssh-ed25519'
        $result.PublicKeyLine | Should -BeLike 'ssh-ed25519 AAAA* convert-test'
        $result.Comment | Should -Be 'convert-test'
        $result.Fingerprint | Should -BeLike 'SHA256:*'
    }

    It 'matches the original .pub file' {
        $result = ConvertTo-SSHPublicKey -Path $script:ConvertKeyPath
        $originalPub = (Get-Content "$($script:ConvertKeyPath).pub" -Raw).Trim()
        $result.PublicKeyLine | Should -Be $originalPub
    }

    It 'extracts from encrypted key with passphrase' {
        $encPath = Join-Path $script:TempDir 'convert_encrypted'
        $pass = ConvertTo-SecureString 'mypass' -AsPlainText -Force
        New-SSHKeyPair -Path $encPath -KeyType Ed25519 -Passphrase $pass -Comment 'enc-convert'

        $result = ConvertTo-SSHPublicKey -Path $encPath -Passphrase $pass
        $result.KeyType | Should -Be 'ssh-ed25519'
        $result.Comment | Should -Be 'enc-convert'
    }

    It 'errors on missing file' {
        { ConvertTo-SSHPublicKey -Path '/nonexistent/key' -ErrorAction Stop } |
            Should -Throw '*not found*'
    }

    It 'accepts pipeline input' {
        $keyPath = Join-Path $script:TempDir 'convert_pipeline'
        New-SSHKeyPair -Path $keyPath -KeyType Ed25519 -Comment 'pipe-test'
        $result = Get-Item $keyPath | ConvertTo-SSHPublicKey
        $result.KeyType | Should -Be 'ssh-ed25519'
    }
}

Describe 'Get-SSHKeyFingerprint' {
    BeforeAll {
        $script:FpKeyPath = Join-Path $script:TempDir 'fp_ed25519'
        New-SSHKeyPair -Path $script:FpKeyPath -KeyType Ed25519 -Comment 'fp-test'
    }

    It 'shows fingerprint of a public key file' {
        $result = Get-SSHKeyFingerprint -Path "$($script:FpKeyPath).pub"
        $result.Fingerprint | Should -BeLike 'SHA256:*'
        $result.KeyType | Should -Be 'ssh-ed25519'
        $result.KeyBits | Should -Be 256
        $result.Comment | Should -Be 'fp-test'
    }

    It 'shows fingerprint of a private key file' {
        $result = Get-SSHKeyFingerprint -Path $script:FpKeyPath
        $result.Fingerprint | Should -BeLike 'SHA256:*'
    }

    It 'private and public key fingerprints match' {
        $privFp = Get-SSHKeyFingerprint -Path $script:FpKeyPath
        $pubFp = Get-SSHKeyFingerprint -Path "$($script:FpKeyPath).pub"
        $privFp.Fingerprint | Should -Be $pubFp.Fingerprint
    }

    It 'supports MD5 algorithm' {
        $result = Get-SSHKeyFingerprint -Path "$($script:FpKeyPath).pub" -Algorithm MD5
        $result.Fingerprint | Should -BeLike 'MD5:*'
    }

    It 'shows correct bits for RSA key' {
        $rsaPath = Join-Path $script:TempDir 'fp_rsa'
        New-SSHKeyPair -Path $rsaPath -KeyType RSA -KeySize 2048 -Comment 'rsa-fp'
        $result = Get-SSHKeyFingerprint -Path "$rsaPath.pub"
        $result.KeyBits | Should -Be 2048
    }
}

Describe 'Test-SSHKeyFile' {
    BeforeAll {
        $script:ValidKeyPath = Join-Path $script:TempDir 'valid_ed25519'
        New-SSHKeyPair -Path $script:ValidKeyPath -KeyType Ed25519 -Comment 'valid-test'
    }

    It 'validates a valid private key' {
        $result = Test-SSHKeyFile -Path $script:ValidKeyPath
        $result.Valid | Should -BeTrue
        $result.KeyType | Should -Be 'ssh-ed25519'
        $result.Format | Should -Be 'OpenSSH Private Key'
        $result.Encrypted | Should -BeFalse
    }

    It 'validates a valid public key' {
        $result = Test-SSHKeyFile -Path "$($script:ValidKeyPath).pub"
        $result.Valid | Should -BeTrue
        $result.KeyType | Should -Be 'ssh-ed25519'
        $result.Format | Should -Be 'OpenSSH Public Key'
    }

    It 'detects encrypted keys' {
        $encPath = Join-Path $script:TempDir 'validate_encrypted'
        $pass = ConvertTo-SecureString 'secret' -AsPlainText -Force
        New-SSHKeyPair -Path $encPath -KeyType Ed25519 -Passphrase $pass -Comment 'enc'

        $result = Test-SSHKeyFile -Path $encPath
        $result.Encrypted | Should -BeTrue
        $result.Valid | Should -BeFalse
        $result.Error | Should -BeLike '*Passphrase*'
    }

    It 'validates encrypted key with correct passphrase' {
        $encPath = Join-Path $script:TempDir 'validate_enc_pass'
        $pass = ConvertTo-SecureString 'secret2' -AsPlainText -Force
        New-SSHKeyPair -Path $encPath -KeyType Ed25519 -Passphrase $pass -Comment 'enc2'

        $result = Test-SSHKeyFile -Path $encPath -Passphrase $pass
        $result.Valid | Should -BeTrue
        $result.Encrypted | Should -BeTrue
    }

    It 'reports error for nonexistent file' {
        $result = Test-SSHKeyFile -Path '/no/such/file'
        $result.Valid | Should -BeFalse
        $result.Error | Should -Be 'File not found'
    }

    It 'reports error for invalid content' {
        $junkPath = Join-Path $script:TempDir 'junk.key'
        'this is not a key' | Set-Content $junkPath
        $result = Test-SSHKeyFile -Path $junkPath
        $result.Valid | Should -BeFalse
        $result.Error | Should -BeLike '*Unrecognized*'
    }

    It 'accepts pipeline input from Get-ChildItem' {
        $results = Get-Item $script:ValidKeyPath | Test-SSHKeyFile
        $results.Valid | Should -BeTrue
    }
}
