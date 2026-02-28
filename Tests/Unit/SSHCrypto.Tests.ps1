BeforeAll {
    # Load the crypto engine
    $initPath = Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Private' 'Initialize-SSHCrypto.ps1'
    . $initPath
    Initialize-SSHCrypto
}

Describe 'PwSSH.Crypto.Ed25519' {
    Context 'Key generation from seed' {
        It 'generates correct public key for RFC 8032 test vector 1' {
            # RFC 8032 Section 7.1 — TEST 1
            $seed = [byte[]]@(
                0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
                0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
                0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
            )
            $expectedPub = [byte[]]@(
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
                0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
                0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0xf4, 0xa1,
                0x84, 0x46, 0xb0, 0xb8, 0xd1, 0x83, 0xf8, 0xe3
            )

            $pubKey = $null
            $expandedPriv = $null
            [PwSSH.Crypto.Ed25519]::GenerateKeyPair($seed, [ref]$pubKey, [ref]$expandedPriv)

            $pubKey | Should -Be $expectedPub
        }

        It 'generates correct public key for RFC 8032 test vector 2' {
            $seed = [byte[]]@(
                0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
                0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
                0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
                0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
            )
            $expectedPub = [byte[]]@(
                0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
                0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
                0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
                0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
            )

            $pubKey = $null
            $expandedPriv = $null
            [PwSSH.Crypto.Ed25519]::GenerateKeyPair($seed, [ref]$pubKey, [ref]$expandedPriv)

            $pubKey | Should -Be $expectedPub
        }

        It 'returns 32-byte public key' {
            $seed = [byte[]]::new(32)
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($seed)

            $pubKey = $null
            $expandedPriv = $null
            [PwSSH.Crypto.Ed25519]::GenerateKeyPair($seed, [ref]$pubKey, [ref]$expandedPriv)

            $pubKey.Length | Should -Be 32
        }

        It 'returns 64-byte expanded private key (seed + pubkey)' {
            $seed = [byte[]]::new(32)
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($seed)

            $pubKey = $null
            $expandedPriv = $null
            [PwSSH.Crypto.Ed25519]::GenerateKeyPair($seed, [ref]$pubKey, [ref]$expandedPriv)

            $expandedPriv.Length | Should -Be 64
            # First 32 bytes should be the seed
            $expandedPriv[0..31] | Should -Be $seed
            # Last 32 bytes should be the public key
            $expandedPriv[32..63] | Should -Be $pubKey
        }

        It 'throws on invalid seed length' {
            $seed = [byte[]]::new(16)
            { [PwSSH.Crypto.Ed25519]::GenerateKeyPair($seed, [ref]$null, [ref]$null) } |
                Should -Throw '*32 bytes*'
        }

        It 'generates different keys for different seeds' {
            $seed1 = [byte[]]::new(32); $seed1[0] = 1
            $seed2 = [byte[]]::new(32); $seed2[0] = 2

            $pub1 = $null; $priv1 = $null
            $pub2 = $null; $priv2 = $null
            [PwSSH.Crypto.Ed25519]::GenerateKeyPair($seed1, [ref]$pub1, [ref]$priv1)
            [PwSSH.Crypto.Ed25519]::GenerateKeyPair($seed2, [ref]$pub2, [ref]$priv2)

            $pub1 | Should -Not -Be $pub2
        }
    }

    Context 'Point encoding/decoding roundtrip' {
        It 'roundtrips a generated public key' {
            $seed = [byte[]]::new(32); $seed[0] = 42
            $pubKey = $null; $priv = $null
            [PwSSH.Crypto.Ed25519]::GenerateKeyPair($seed, [ref]$pubKey, [ref]$priv)

            $x = [System.Numerics.BigInteger]::Zero
            $y = [System.Numerics.BigInteger]::Zero
            [PwSSH.Crypto.Ed25519]::DecodePoint($pubKey, [ref]$x, [ref]$y)

            $reEncoded = [PwSSH.Crypto.Ed25519]::EncodePoint($x, $y)
            $reEncoded | Should -Be $pubKey
        }
    }
}

Describe 'PwSSH.Crypto.SshWireFormat' {
    Context 'UInt32 roundtrip' {
        It 'writes and reads UInt32 correctly' {
            $ms = [System.IO.MemoryStream]::new()
            [PwSSH.Crypto.SshWireFormat]::WriteUInt32($ms, 0x12345678)
            $ms.Position = 0
            $result = [PwSSH.Crypto.SshWireFormat]::ReadUInt32($ms)
            $result | Should -Be 0x12345678
            $ms.Dispose()
        }
    }

    Context 'String roundtrip' {
        It 'writes and reads ASCII strings' {
            $ms = [System.IO.MemoryStream]::new()
            [PwSSH.Crypto.SshWireFormat]::WriteString($ms, 'ssh-ed25519')
            $ms.Position = 0
            $result = [PwSSH.Crypto.SshWireFormat]::ReadString($ms)
            $result | Should -Be 'ssh-ed25519'
            $ms.Dispose()
        }
    }

    Context 'Bytes roundtrip' {
        It 'writes and reads byte arrays' {
            $data = [byte[]]@(1, 2, 3, 4, 5)
            $ms = [System.IO.MemoryStream]::new()
            [PwSSH.Crypto.SshWireFormat]::WriteBytes($ms, $data)
            $ms.Position = 0
            $result = [PwSSH.Crypto.SshWireFormat]::ReadBytes($ms)
            $result | Should -Be $data
            $ms.Dispose()
        }
    }

    Context 'MPInt roundtrip' {
        It 'roundtrips positive integers' {
            $val = [System.Numerics.BigInteger]::Parse('123456789012345678901234567890')
            $ms = [System.IO.MemoryStream]::new()
            [PwSSH.Crypto.SshWireFormat]::WriteMPInt($ms, $val)
            $ms.Position = 0
            $result = [PwSSH.Crypto.SshWireFormat]::ReadMPInt($ms)
            $result | Should -Be $val
            $ms.Dispose()
        }

        It 'handles zero' {
            $ms = [System.IO.MemoryStream]::new()
            [PwSSH.Crypto.SshWireFormat]::WriteMPInt($ms, [System.Numerics.BigInteger]::Zero)
            $ms.Position = 0
            $result = [PwSSH.Crypto.SshWireFormat]::ReadMPInt($ms)
            $result | Should -Be ([System.Numerics.BigInteger]::Zero)
            $ms.Dispose()
        }
    }
}

Describe 'PwSSH.Crypto.BcryptPbkdf' {
    It 'derives key material of requested length' {
        $pass = [System.Text.Encoding]::UTF8.GetBytes('testpassword')
        $salt = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)

        $result = [PwSSH.Crypto.BcryptPbkdf]::DeriveKey($pass, $salt, 4, 48)
        $result.Length | Should -Be 48
    }

    It 'produces different output for different passwords' {
        $salt = [byte[]]@(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)
        $pass1 = [System.Text.Encoding]::UTF8.GetBytes('password1')
        $pass2 = [System.Text.Encoding]::UTF8.GetBytes('password2')

        $key1 = [PwSSH.Crypto.BcryptPbkdf]::DeriveKey($pass1, $salt, 4, 32)
        $key2 = [PwSSH.Crypto.BcryptPbkdf]::DeriveKey($pass2, $salt, 4, 32)

        $key1 | Should -Not -Be $key2
    }

    It 'produces different output for different salts' {
        $pass = [System.Text.Encoding]::UTF8.GetBytes('samepassword')
        $salt1 = [byte[]]@(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)
        $salt2 = [byte[]]@(16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1)

        $key1 = [PwSSH.Crypto.BcryptPbkdf]::DeriveKey($pass, $salt1, 4, 32)
        $key2 = [PwSSH.Crypto.BcryptPbkdf]::DeriveKey($pass, $salt2, 4, 32)

        $key1 | Should -Not -Be $key2
    }

    It 'is deterministic for same inputs' {
        $pass = [System.Text.Encoding]::UTF8.GetBytes('deterministic')
        $salt = [byte[]]@(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)

        $key1 = [PwSSH.Crypto.BcryptPbkdf]::DeriveKey($pass, $salt, 4, 32)
        $key2 = [PwSSH.Crypto.BcryptPbkdf]::DeriveKey($pass, $salt, 4, 32)

        $key1 | Should -Be $key2
    }
}

Describe 'PwSSH.Crypto.AesCtr' {
    It 'encrypts and decrypts back to original' {
        $key = [byte[]]::new(32)
        $iv = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

        $plaintext = [System.Text.Encoding]::UTF8.GetBytes('Hello, AES-CTR encryption test!')
        $ciphertext = [PwSSH.Crypto.AesCtr]::Transform($key, $iv, $plaintext)
        $decrypted = [PwSSH.Crypto.AesCtr]::Transform($key, $iv, $ciphertext)

        $decrypted | Should -Be $plaintext
    }

    It 'produces different ciphertext from plaintext' {
        $key = [byte[]]::new(32); $key[0] = 1
        $iv = [byte[]]::new(16); $iv[0] = 1
        $plaintext = [System.Text.Encoding]::UTF8.GetBytes('secret data here')

        $ciphertext = [PwSSH.Crypto.AesCtr]::Transform($key, $iv, $plaintext)
        $ciphertext | Should -Not -Be $plaintext
    }
}

Describe 'PwSSH.Crypto.OpenSshKeyFormat' {
    Context 'Ed25519 key generation' {
        It 'generates a valid Ed25519 key' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('test@host')
            $key.KeyType | Should -Be 'ssh-ed25519'
            $key.Comment | Should -Be 'test@host'
            $key.Ed25519Seed.Length | Should -Be 32
            $key.Ed25519PublicKey.Length | Should -Be 32
            $key.PublicKeyBlob | Should -Not -BeNullOrEmpty
        }
    }

    Context 'RSA key generation' {
        It 'generates a valid RSA key' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateRsa(2048, 'test@host')
            $key.KeyType | Should -Be 'ssh-rsa'
            $key.Comment | Should -Be 'test@host'
            $key.PublicKeyBlob | Should -Not -BeNullOrEmpty
        }
    }

    Context 'ECDSA key generation' {
        It 'generates a valid ECDSA-256 key' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEcdsa(256, 'test@host')
            $key.KeyType | Should -Be 'ecdsa-sha2-nistp256'
            $key.EcCurveName | Should -Be 'nistp256'
        }

        It 'generates a valid ECDSA-384 key' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEcdsa(384, 'test@host')
            $key.KeyType | Should -Be 'ecdsa-sha2-nistp384'
            $key.EcCurveName | Should -Be 'nistp384'
        }
    }

    Context 'Public key formatting' {
        It 'formats a public key line correctly' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('user@box')
            $line = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPublicKeyLine($key)
            $line | Should -BeLike 'ssh-ed25519 AAAA* user@box'
        }
    }

    Context 'Private key file format — unencrypted' {
        It 'formats a valid OpenSSH private key PEM' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('test')
            $pem = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPrivateKeyFile($key, $null)
            $pem | Should -BeLike '*-----BEGIN OPENSSH PRIVATE KEY-----*'
            $pem | Should -BeLike '*-----END OPENSSH PRIVATE KEY-----*'
        }

        It 'can parse back what it wrote (Ed25519)' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('roundtrip')
            $pem = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPrivateKeyFile($key, $null)
            $parsed = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($pem, $null)

            $parsed.KeyType | Should -Be 'ssh-ed25519'
            $parsed.Comment | Should -Be 'roundtrip'
            $parsed.Ed25519Seed | Should -Be $key.Ed25519Seed
            $parsed.Ed25519PublicKey | Should -Be $key.Ed25519PublicKey
        }

        It 'can parse back what it wrote (RSA)' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateRsa(2048, 'rsa-test')
            $pem = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPrivateKeyFile($key, $null)
            $parsed = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($pem, $null)

            $parsed.KeyType | Should -Be 'ssh-rsa'
            $parsed.Comment | Should -Be 'rsa-test'
        }
    }

    Context 'Private key file format — encrypted' {
        It 'can encrypt and decrypt an Ed25519 key with passphrase' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('encrypted')
            $pem = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPrivateKeyFile($key, 'mysecret')

            # Should fail without passphrase
            { [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($pem, $null) } |
                Should -Throw '*encrypted*'

            # Should succeed with correct passphrase
            $parsed = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($pem, 'mysecret')
            $parsed.KeyType | Should -Be 'ssh-ed25519'
            $parsed.Ed25519Seed | Should -Be $key.Ed25519Seed
        }

        It 'rejects wrong passphrase' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('encrypted')
            $pem = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPrivateKeyFile($key, 'correct')

            { [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($pem, 'wrong') } |
                Should -Throw '*passphrase*'
        }
    }

    Context 'Public key line parsing' {
        It 'parses an Ed25519 public key line' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('parse-test')
            $line = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPublicKeyLine($key)
            $parsed = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePublicKeyLine($line)

            $parsed.KeyType | Should -Be 'ssh-ed25519'
            $parsed.Comment | Should -Be 'parse-test'
            $parsed.Ed25519PublicKey | Should -Be $key.Ed25519PublicKey
        }
    }

    Context 'Fingerprint' {
        It 'generates SHA256 fingerprint' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('fp-test')
            $fp = [PwSSH.Crypto.OpenSshKeyFormat]::Fingerprint($key.PublicKeyBlob, 'SHA256')
            $fp | Should -BeLike 'SHA256:*'
        }

        It 'generates MD5 fingerprint' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('fp-test')
            $fp = [PwSSH.Crypto.OpenSshKeyFormat]::Fingerprint($key.PublicKeyBlob, 'MD5')
            $fp | Should -BeLike 'MD5:*'
            $fp | Should -Match 'MD5:[0-9a-f]{2}(:[0-9a-f]{2}){15}'
        }

        It 'produces consistent fingerprints' {
            $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('fp-test')
            $fp1 = [PwSSH.Crypto.OpenSshKeyFormat]::Fingerprint($key.PublicKeyBlob, 'SHA256')
            $fp2 = [PwSSH.Crypto.OpenSshKeyFormat]::Fingerprint($key.PublicKeyBlob, 'SHA256')
            $fp1 | Should -Be $fp2
        }
    }
}
