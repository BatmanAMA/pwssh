BeforeAll {
    . (Join-Path $PSScriptRoot '..' '..' 'src' 'pwssh' 'Private' 'ConvertTo-SSHFingerprint.ps1')
}

Describe 'ConvertTo-SSHFingerprint' {
    BeforeAll {
        # Known test data — a simple byte array
        $testData = [byte[]]@(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
    }

    It 'returns a SHA256 fingerprint by default' {
        $result = ConvertTo-SSHFingerprint -KeyData $testData
        $result | Should -BeLike 'SHA256:*'
    }

    It 'returns a SHA256 fingerprint when specified' {
        $result = ConvertTo-SSHFingerprint -KeyData $testData -Algorithm SHA256
        $result | Should -BeLike 'SHA256:*'
    }

    It 'returns an MD5 fingerprint when specified' {
        $result = ConvertTo-SSHFingerprint -KeyData $testData -Algorithm MD5
        $result | Should -BeLike 'MD5:*'
        # MD5 fingerprints use colon-separated hex
        $result | Should -Match 'MD5:[0-9a-f]{2}(:[0-9a-f]{2}){15}'
    }

    It 'produces consistent SHA256 output for same input' {
        $result1 = ConvertTo-SSHFingerprint -KeyData $testData -Algorithm SHA256
        $result2 = ConvertTo-SSHFingerprint -KeyData $testData -Algorithm SHA256
        $result1 | Should -Be $result2
    }

    It 'produces consistent MD5 output for same input' {
        $result1 = ConvertTo-SSHFingerprint -KeyData $testData -Algorithm MD5
        $result2 = ConvertTo-SSHFingerprint -KeyData $testData -Algorithm MD5
        $result1 | Should -Be $result2
    }

    It 'produces different fingerprints for different data' {
        $otherData = [byte[]]@(255, 254, 253, 252)
        $fp1 = ConvertTo-SSHFingerprint -KeyData $testData -Algorithm SHA256
        $fp2 = ConvertTo-SSHFingerprint -KeyData $otherData -Algorithm SHA256
        $fp1 | Should -Not -Be $fp2
    }

    It 'SHA256 fingerprint does not end with equals sign' {
        $result = ConvertTo-SSHFingerprint -KeyData $testData -Algorithm SHA256
        $result | Should -Not -Match '=$'
    }
}
