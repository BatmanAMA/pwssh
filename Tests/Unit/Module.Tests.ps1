# Loads the real module through its manifest, the way a user does. The other unit
# tests dot-source the functions, which cannot catch load-order or export problems.

BeforeAll {
    $script:Manifest = Join-Path (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'src') 'pwssh'
    $script:Manifest = Join-Path $script:Manifest 'pwssh.psd1'
    $script:Module = Import-Module $script:Manifest -Force -PassThru -WarningAction SilentlyContinue
}

AfterAll {
    Remove-Module pwssh -Force -ErrorAction SilentlyContinue
}

Describe 'pwssh module' {
    It 'has a valid manifest' {
        { Test-ModuleManifest -Path $script:Manifest -ErrorAction Stop -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'imports' {
        $script:Module | Should -Not -BeNullOrEmpty
        $script:Module.Name | Should -Be 'pwssh'
    }

    It 'exports exactly the functions listed in the manifest' {
        $declared = (Import-PowerShellDataFile $script:Manifest).FunctionsToExport | Sort-Object
        $actual = $script:Module.ExportedFunctions.Keys | Sort-Object
        $actual | Should -Be $declared
    }

    It 'has a source file for every exported function' {
        $publicDir = Join-Path (Split-Path $script:Manifest -Parent) 'Public'
        foreach ($name in $script:Module.ExportedFunctions.Keys) {
            Join-Path $publicDir "$name.ps1" | Should -Exist
        }
    }

    It 'does not export private helpers' {
        Get-Command -Module pwssh -Name 'Get-SSHAuthMethod', 'Resolve-SSHLocalPath' -ErrorAction SilentlyContinue |
            Should -BeNullOrEmpty
    }

    It 'makes the output types resolvable' {
        foreach ($t in 'SSHSessionInfo', 'SSHCommandResult', 'SSHPortForward', 'SSHHostKey', 'SSHKnownHost') {
            ($t -as [type]) | Should -Not -BeNullOrEmpty -Because "$t must be visible to callers"
        }
    }

    It 'attaches the script members from the types file' {
        $session = [SSHSessionInfo]::new()
        $session.PSObject.Methods['Disconnect'] | Should -Not -BeNullOrEmpty
        $session.PSObject.Properties['IsAlive'] | Should -Not -BeNullOrEmpty
        [SSHPortForward]::new().PSObject.Methods['Stop'] | Should -Not -BeNullOrEmpty
        $result = [SSHCommandResult]::new()
        $result.ExitCode = 0
        $result.Success | Should -BeTrue
    }

    It 'gives every exported function a synopsis' {
        foreach ($name in $script:Module.ExportedFunctions.Keys) {
            (Get-Help $name).Synopsis.Trim() | Should -Not -BeLike "$name*" -Because "$name needs comment-based help"
        }
    }

    It 'works end to end for key management without SSH.NET' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_mod_$([guid]::NewGuid().ToString('N'))"
        try {
            $key = New-SSHKeyPair -Path (Join-Path $dir 'id_test') -Comment 'module test'
            $key.Fingerprint | Should -BeLike 'SHA256:*'
            (Test-SSHKeyFile -Path $key.PrivateKeyPath).Valid | Should -BeTrue
            (Get-SSHKeyFingerprint -Path $key.PublicKeyPath).Fingerprint | Should -Be $key.Fingerprint
        }
        finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'pwssh error behaviour' {
    It 'writes non-terminating errors unless the caller asks otherwise' {
        $after = & { Get-SSHSession -SessionId 987654 -ErrorAction SilentlyContinue; 'after' }
        $after | Should -Be 'after'
        $result = & { Invoke-SSHCommand -SessionId 987654 -Command 'true' 2>$null; 'continued' }
        $result | Should -Be 'continued'
        { Invoke-SSHCommand -SessionId 987654 -Command 'true' -ErrorAction Stop } | Should -Throw '*not found*'
    }

    It 'reports an empty passphrase as an unencrypted key' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "pwssh_mod_$([guid]::NewGuid().ToString('N'))"
        try {
            $key = New-SSHKeyPair -Path (Join-Path $dir 'id_empty') -Passphrase ([securestring]::new())
            $key.Encrypted | Should -BeFalse
            (Test-SSHKeyFile -Path $key.PrivateKeyPath).Encrypted | Should -BeFalse
        }
        finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
