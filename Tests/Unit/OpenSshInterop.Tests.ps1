BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelper.ps1')

    function ConvertFrom-Hex([string]$Hex) {
        $bytes = [byte[]]::new($Hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
        , $bytes
    }
    function ConvertTo-Hex([byte[]]$Bytes) { ($Bytes | ForEach-Object { $_.ToString('x2') }) -join '' }

    $script:SshKeygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
}

# These tests pin the module's key handling to what OpenSSH actually does, rather
# than to its own reader: a writer and reader that share a bug round-trip happily.

Describe 'bcrypt_pbkdf known answers' {
    # Reference values produced by the OpenBSD implementation (via the Python
    # "bcrypt" package, bcrypt.kdf).
    It 'matches the reference for <Password> / <Rounds> rounds / <Length> bytes' -ForEach @(
        @{ Password = 'password'; SaltHex = '73616c74';                         Rounds = 4;  Length = 32
           Expected = '5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9' }
        @{ Password = 'password'; SaltHex = '00000000000000000000000000000000'; Rounds = 8;  Length = 48
           Expected = 'e55adfa0551f0173bc9dcbdeabb740d5664c0ea028ed90cbf89ad41a1dbacbf386eb2c056f3f8664e51a4c1d516a1392' }
        @{ Password = 'hunter2';  SaltHex = '000102030405060708090a0b0c0d0e0f'; Rounds = 16; Length = 48
           Expected = '76903cbe9474a3ba898308c55ddddd574d7d7d8aeecff6200b408d39b9e09bd82f79ea4d43f236fa8dd765260a93a96a' }
        @{ Password = ('p' + [char]0xE4 + 'ssword'); SaltHex = '4e61436c4e61436c4e61436c4e61436c'; Rounds = 2; Length = 64
           Expected = '62c91c1cac7b6b4a06d45d7e54be4efcb3791f3f7bfc4de1c63550d3624236842bf7fca07d152a98d7e7a6134c98a3fb039b0a75f6ee6aee60cf55d64cb6c2a9' }
    ) {
        $pass = [System.Text.Encoding]::UTF8.GetBytes($Password)
        $derived = [PwSSH.Crypto.BcryptPbkdf]::DeriveKey($pass, (ConvertFrom-Hex $SaltHex), $Rounds, $Length)
        ConvertTo-Hex $derived | Should -Be $Expected
    }
}

Describe 'mpint encoding (RFC 4251)' {
    It 'encodes <Value> as <Expected>' -ForEach @(
        @{ Value = '0';     Expected = '00000000' }
        @{ Value = '127';   Expected = '000000017f' }
        @{ Value = '128';   Expected = '000000020080' }       # top bit set: needs a leading zero
        @{ Value = '65535'; Expected = '0000000300ffff' }
        @{ Value = '256';   Expected = '000000020100' }
    ) {
        $ms = [System.IO.MemoryStream]::new()
        [PwSSH.Crypto.SshWireFormat]::WriteMPInt($ms, [System.Numerics.BigInteger]::Parse($Value))
        ConvertTo-Hex $ms.ToArray() | Should -Be $Expected
    }

    It 'writes the RSA modulus as a positive number' {
        $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateRsa(2048, 'test')
        $ms = [System.IO.MemoryStream]::new($key.PublicKeyBlob)
        [PwSSH.Crypto.SshWireFormat]::ReadString($ms) | Should -Be 'ssh-rsa'
        [void][PwSSH.Crypto.SshWireFormat]::ReadBytes($ms)           # e
        $n = [PwSSH.Crypto.SshWireFormat]::ReadBytes($ms)
        $n.Length | Should -Be 257
        $n[0] | Should -Be 0
        $n[1] | Should -BeGreaterOrEqual 0x80
    }
}

Describe 'Reading a key written by ssh-keygen' {
    BeforeAll {
        # Throwaway key generated with: ssh-keygen -t ed25519 -N fixture-pass
        # It protects nothing; it exists only as a test vector.
        $script:FixturePrivate = @'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDZtrlnhS
EXDo1kqbDIoMldAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJ1ykiD6Tw5Ih+39
fiyfOK3UCsrrcyn3bEwuZeRrMbLRAAAAoE9FTNDgkoYXfdyA+vvaHVS+t/obKznG8+xU14
Pa/wRN2e1SpUTmuTNsmbtnb3Nb/KfSLAeEIKQKBN7HKYxsHUrbF2RBoZHTzcUzzTGHo6AO
OsDjtuHnQelGqRGPE7b8aLmdA1TV6OZ6gE0mY9pcT3q62x7XrL8hBGdfiqT2XWWcVpkS9A
llKcHT14V+WgiJRa0W3D365iFmlSOEnjOr5LI=
-----END OPENSSH PRIVATE KEY-----
'@
        $script:FixturePublic = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1ykiD6Tw5Ih+39fiyfOK3UCsrrcyn3bEwuZeRrMbLR pwssh-test-fixture'
    }

    It 'decrypts an aes256-ctr/bcrypt key with the right passphrase' {
        $key = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($script:FixturePrivate, 'fixture-pass')
        $key.KeyType | Should -Be 'ssh-ed25519'
        $key.Comment | Should -Be 'pwssh-test-fixture'
        [PwSSH.Crypto.OpenSshKeyFormat]::FormatPublicKeyLine($key) | Should -Be $script:FixturePublic
    }

    It 'derives the stored public key from the decrypted seed' {
        $key = [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($script:FixturePrivate, 'fixture-pass')
        $pub = $null; $expanded = $null
        [PwSSH.Crypto.Ed25519]::GenerateKeyPair($key.Ed25519Seed, [ref]$pub, [ref]$expanded)
        ConvertTo-Hex $pub | Should -Be (ConvertTo-Hex $key.Ed25519PublicKey)
    }

    It 'rejects a wrong passphrase' {
        { [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($script:FixturePrivate, 'wrong') } |
            Should -Throw '*Incorrect passphrase*'
    }

    It 'reports the cipher without needing the passphrase' {
        [PwSSH.Crypto.OpenSshKeyFormat]::GetCipherName($script:FixturePrivate) | Should -Be 'aes256-ctr'
    }
}

Describe 'Hardened private key parsing' {
    It 'rejects text that is not an OpenSSH key' {
        { [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile('hello', $null) } | Should -Throw '*Not an OpenSSH private key*'
    }

    It 'rejects a truncated key' {
        $key = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('t')
        $pem = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPrivateKeyFile($key, $null)
        $lines = $pem.Trim() -split "`n"
        $broken = ($lines[0], $lines[1].Substring(0, 40), $lines[-1]) -join "`n"
        { [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($broken, $null) } | Should -Throw
    }

    It 'rejects a key whose public and private halves differ' {
        $a = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('a')
        $b = [PwSSH.Crypto.OpenSshKeyFormat]::GenerateEd25519('b')
        $a.PublicKeyBlob = $b.PublicKeyBlob      # outer (cleartext) blob no longer matches
        $pem = [PwSSH.Crypto.OpenSshKeyFormat]::FormatPrivateKeyFile($a, $null)
        { [PwSSH.Crypto.OpenSshKeyFormat]::ParsePrivateKeyFile($pem, $null) } | Should -Throw '*do not match*'
    }

    It 'refuses RSA keys below 2048 bits' {
        { [PwSSH.Crypto.OpenSshKeyFormat]::GenerateRsa(1024, 't') } | Should -Throw
    }
}

Describe 'Keys accepted by ssh-keygen' -Skip:(-not (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
    BeforeAll {
        $script:KeyDir = New-TestDirectory
        $script:Pass = ConvertTo-SecureString 'interop pass' -AsPlainText -Force
    }
    AfterAll {
        Remove-Item -LiteralPath $script:KeyDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'ssh-keygen reads an unencrypted <Type> <Size> key' -ForEach @(
        @{ Type = 'Ed25519'; Size = 0 }
        @{ Type = 'RSA';     Size = 2048 }
        @{ Type = 'ECDSA';   Size = 256 }
        @{ Type = 'ECDSA';   Size = 384 }
        @{ Type = 'ECDSA';   Size = 521 }
    ) {
        $path = Join-Path $script:KeyDir "plain_${Type}_$Size"
        $null = New-SSHKeyPair -Path $path -KeyType $Type -KeySize $Size -Comment 'interop'
        $derived = & ssh-keygen -y -f $path 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "$derived"
        ("$derived" -split ' ')[1] | Should -Be ((Get-Content "$path.pub") -split ' ')[1]
        & ssh-keygen -l -f "$path.pub" 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    It 'ssh-keygen decrypts a passphrase-protected <Type> key' -ForEach @(
        @{ Type = 'Ed25519' }
        @{ Type = 'RSA' }
        @{ Type = 'ECDSA' }
    ) {
        $path = Join-Path $script:KeyDir "enc_$Type"
        $size = if ($Type -eq 'RSA') { 2048 } else { 0 }
        $null = New-SSHKeyPair -Path $path -KeyType $Type -KeySize $size -Comment 'interop' -Passphrase $script:Pass
        $derived = & ssh-keygen -y -P 'interop pass' -f $path 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "$derived"
        ("$derived" -split ' ')[1] | Should -Be ((Get-Content "$path.pub") -split ' ')[1]
    }

    It 'every ECDSA key is valid, whatever the top bit of the private scalar' {
        foreach ($i in 1..8) {
            $path = Join-Path $script:KeyDir "ec_$i"
            $null = New-SSHKeyPair -Path $path -KeyType ECDSA -Comment 'interop'
            & ssh-keygen -y -f $path 2>&1 | Out-Null
            $LASTEXITCODE | Should -Be 0
        }
    }

    It 'reads a <Type> key generated by ssh-keygen' -ForEach @(
        @{ Type = 'ed25519'; Bits = 256 }
        @{ Type = 'rsa';     Bits = 3072 }
        @{ Type = 'ecdsa';   Bits = 521 }
    ) {
        $path = Join-Path $script:KeyDir "openssh_$Type"
        & ssh-keygen -q -t $Type -b $Bits -N 'interop pass' -C 'made by openssh' -f $path
        $LASTEXITCODE | Should -Be 0
        $pub = ConvertTo-SSHPublicKey -Path $path -Passphrase $script:Pass
        $pub.PublicKeyLine | Should -Be (Get-Content "$path.pub")
        (Test-SSHKeyFile -Path $path -Passphrase $script:Pass).Valid | Should -BeTrue
    }

    It 'creates the private key readable by its owner only' -Skip:($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
        $path = Join-Path $script:KeyDir 'perm_test'
        $null = New-SSHKeyPair -Path $path -Comment 'perm'
        $mode = & stat -c '%a' $path 2>$null
        if (-not $mode) { $mode = & stat -f '%Lp' $path }
        $mode | Should -Be '600'
    }
}
