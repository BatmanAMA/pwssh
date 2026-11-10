BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'TestHelper.ps1')

    $script:Dir = New-TestDirectory

    function New-Blob([string]$KeyType = 'ssh-ed25519') {
        , [System.Convert]::FromBase64String((New-TestHostKeyData -KeyType $KeyType))
    }
    function ConvertTo-B64([byte[]]$Blob) { [System.Convert]::ToBase64String($Blob) }

    function New-KnownHosts([string[]]$Lines) {
        $path = Join-Path $script:Dir ("kh_" + [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($path, (($Lines -join "`n") + "`n"))
        $path
    }

    function Get-Status([string]$Path, [string]$HostName, [int]$Port, [byte[]]$Blob) {
        [PwSSH.KnownHostsFile]::Check([string[]]@($Path), $HostName, $Port, $Blob).Status.ToString()
    }

    function New-Verifier([string]$Mode, [string]$Path, [string]$HostName = 'host.example', [int]$Port = 22) {
        $v = [PwSSH.HostKeyVerifier]::new()
        $v.Mode = [PwSSH.HostKeyMode]$Mode
        $v.Host = $HostName
        $v.Port = $Port
        $v.KnownHostsPaths = [string[]]@($Path)
        $v.UserKnownHostsPath = $Path
        $v
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'known_hosts lookup (PwSSH.KnownHostsFile.Check)' {
    BeforeAll {
        $script:Key = New-Blob
        $script:Other = New-Blob
        $script:RsaKey = New-Blob 'ssh-rsa'
    }

    It 'reports an unknown host as New' {
        $kh = New-KnownHosts "other.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'New'
    }

    It 'reports a missing file as New' {
        Get-Status (Join-Path $script:Dir 'nope') 'host.example' 22 $script:Key | Should -Be 'New'
    }

    It 'accepts a matching key' {
        $kh = New-KnownHosts "host.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'Ok'
    }

    It 'matches host names case-insensitively' {
        $kh = New-KnownHosts "Host.Example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'HOST.example' 22 $script:Key | Should -Be 'Ok'
    }

    It 'reports a different key of the same type as Changed' {
        $kh = New-KnownHosts "host.example ssh-ed25519 $(ConvertTo-B64 $script:Other)"
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'Changed'
    }

    It 'reports a key of a different type as Changed, like OpenSSH' {
        # A host known by its RSA key that suddenly offers only an unknown Ed25519 key
        # must not be treated as a first contact.
        $kh = New-KnownHosts "host.example ssh-rsa $(ConvertTo-B64 $script:RsaKey)"
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'Changed'
    }

    It 'accepts a key when any of several recorded keys matches' {
        $kh = New-KnownHosts @(
            "host.example ssh-ed25519 $(ConvertTo-B64 $script:Other)"
            "host.example ssh-rsa $(ConvertTo-B64 $script:RsaKey)"
            "host.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        )
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'Ok'
    }

    It 'ignores a trailing comment on the entry' {
        $kh = New-KnownHosts "host.example ssh-ed25519 $(ConvertTo-B64 $script:Key) added by ops 2024"
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'Ok'
    }

    It 'matches hashed entries' {
        $hashed = [PwSSH.KnownHostsFile]::HashHost('host.example')
        $hashed | Should -BeLike '|1|*|*'
        $kh = New-KnownHosts "$hashed ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'Ok'
        Get-Status $kh 'host.example' 22 $script:Other | Should -Be 'Changed'
        Get-Status $kh 'elsewhere.example' 22 $script:Key | Should -Be 'New'
    }

    It 'matches a hashed entry written by OpenSSH' {
        # ssh-keygen -H output for the host name "pwssh-test.example"
        # salt = 20 x 0x01, hash = HMAC-SHA1(salt, name)
        $salt = [byte[]]::new(20); for ($i = 0; $i -lt 20; $i++) { $salt[$i] = 1 }
        $hmac = [System.Security.Cryptography.HMACSHA1]::new($salt)
        $hash = $hmac.ComputeHash([System.Text.Encoding]::ASCII.GetBytes('pwssh-test.example'))
        $hmac.Dispose()
        $field = '|1|' + [Convert]::ToBase64String($salt) + '|' + [Convert]::ToBase64String($hash)
        $kh = New-KnownHosts "$field ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'pwssh-test.example' 22 $script:Key | Should -Be 'Ok'
    }

    It 'uses [host]:port for non-default ports' {
        $kh = New-KnownHosts "[host.example]:2222 ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'host.example' 2222 $script:Key | Should -Be 'Ok'
        Get-Status $kh 'host.example' 2222 $script:Other | Should -Be 'Changed'
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'New'
        Get-Status $kh 'host.example' 2223 $script:Key | Should -Be 'New'
    }

    It 'handles comma lists with a port on each host' {
        $kh = New-KnownHosts "[host.example]:2222,[10.0.0.5]:2222 ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'host.example' 2222 $script:Key | Should -Be 'Ok'
        Get-Status $kh '10.0.0.5' 2222 $script:Other | Should -Be 'Changed'
    }

    It 'falls back to the bare host name for a non-default port' {
        $kh = New-KnownHosts "host.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'host.example' 2222 $script:Key | Should -Be 'Ok'
        # ...but only for an exact key match
        Get-Status $kh 'host.example' 2222 $script:Other | Should -Be 'New'
    }

    It 'honours wildcard patterns' {
        $kh = New-KnownHosts "*.example,10.0.0.? ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'a.example' 22 $script:Key | Should -Be 'Ok'
        Get-Status $kh '10.0.0.7' 22 $script:Key | Should -Be 'Ok'
        Get-Status $kh '10.0.0.77' 22 $script:Key | Should -Be 'New'
        Get-Status $kh 'a.example' 22 $script:Other | Should -Be 'Changed'
    }

    It 'honours negated patterns' {
        $kh = New-KnownHosts "*.example,!bad.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'good.example' 22 $script:Key | Should -Be 'Ok'
        Get-Status $kh 'bad.example' 22 $script:Key | Should -Be 'New'
    }

    It 'refuses a @revoked key even if it is also listed as trusted' {
        $kh = New-KnownHosts @(
            "host.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
            "@revoked * ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        )
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'Revoked'
        Get-Status $kh 'host.example' 2222 $script:Key | Should -Be 'Revoked'
    }

    It 'does not treat @cert-authority lines as host keys' {
        $kh = New-KnownHosts "@cert-authority *.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'New'
        Get-Status $kh 'host.example' 22 $script:Other | Should -Be 'New'
    }

    It 'skips entries with invalid base64 instead of calling them Changed' {
        $kh = New-KnownHosts @(
            'host.example ssh-ed25519 !!!not-base64!!!'
            "host.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        )
        Get-Status $kh 'host.example' 22 $script:Key | Should -Be 'Ok'
    }

    It 'consults every file given' {
        $user = New-KnownHosts '# empty'
        $global = New-KnownHosts "host.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
        [PwSSH.KnownHostsFile]::Check([string[]]@($user, $global), 'host.example', 22, $script:Key).Status.ToString() | Should -Be 'Ok'
    }
}

Describe 'PwSSH.KnownHostsFile.AppendLine' {
    It 'creates the file with a terminated line' {
        $path = Join-Path $script:Dir ("append_" + [guid]::NewGuid().ToString('N'))
        [PwSSH.KnownHostsFile]::AppendLine($path, 'a ssh-ed25519 AAAA')
        [System.IO.File]::ReadAllText($path) | Should -Be "a ssh-ed25519 AAAA`n"
    }

    It 'does not run into an unterminated last line' {
        $path = Join-Path $script:Dir ("append_" + [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($path, 'a ssh-ed25519 AAAA')      # no trailing newline
        [PwSSH.KnownHostsFile]::AppendLine($path, 'b ssh-ed25519 BBBB')
        [System.IO.File]::ReadAllText($path) | Should -Be "a ssh-ed25519 AAAA`nb ssh-ed25519 BBBB`n"
    }

    It 'refuses multi-line input' {
        $path = Join-Path $script:Dir ("append_" + [guid]::NewGuid().ToString('N'))
        { [PwSSH.KnownHostsFile]::AppendLine($path, "a ssh-ed25519 AAAA`nevil ssh-ed25519 BBBB") } | Should -Throw
    }
}

Describe 'PwSSH.HostKeyVerifier' {
    BeforeAll {
        $script:Key = New-Blob
        $script:Other = New-Blob
    }

    Context 'unknown host' {
        It 'Strict refuses and records nothing' {
            $kh = New-KnownHosts '# empty'
            $v = New-Verifier Strict $kh
            $v.Verify($script:Key) | Should -BeFalse
            $v.Status.ToString() | Should -Be 'New'
            $v.Error | Should -BeLike '*StrictHostKeyChecking*'
            (Get-Content $kh).Count | Should -Be 1
        }

        It 'Ask refuses, reports New and records nothing (the caller prompts)' {
            $kh = New-KnownHosts '# empty'
            $v = New-Verifier Ask $kh
            $v.Verify($script:Key) | Should -BeFalse
            $v.Status.ToString() | Should -Be 'New'
            $v.Fingerprint | Should -BeLike 'SHA256:*'
            (Get-Content $kh).Count | Should -Be 1
        }

        It '<Mode> trusts and records the key' -ForEach @(@{ Mode = 'AcceptNew' }, @{ Mode = 'Off' }) {
            $kh = New-KnownHosts '# empty'
            $v = New-Verifier $Mode $kh 'host.example' 2222
            $v.Verify($script:Key) | Should -BeTrue
            (Get-Content $kh)[-1] | Should -Be "[host.example]:2222 ssh-ed25519 $(ConvertTo-B64 $script:Key)"
            # and the recorded entry is what a later strict check accepts
            (New-Verifier Strict $kh 'host.example' 2222).Verify($script:Key) | Should -BeTrue
        }
    }

    Context 'changed host key' {
        It '<Mode> refuses a changed key' -ForEach @(
            @{ Mode = 'Strict' }, @{ Mode = 'Ask' }, @{ Mode = 'AcceptNew' }
        ) {
            $kh = New-KnownHosts "host.example ssh-ed25519 $(ConvertTo-B64 $script:Other)"
            $v = New-Verifier $Mode $kh
            $v.Verify($script:Key) | Should -BeFalse
            $v.Status.ToString() | Should -Be 'Changed'
            $v.Error | Should -BeLike '*REMOTE HOST IDENTIFICATION HAS CHANGED*'
            $v.Error | Should -BeLike "*${kh}:1*"
            # the stale entry is left alone and the new key is not added
            Get-Content $kh | Should -Be "host.example ssh-ed25519 $(ConvertTo-B64 $script:Other)"
        }

        It 'Off refuses a changed key when a password would be sent' {
            $kh = New-KnownHosts "host.example ssh-ed25519 $(ConvertTo-B64 $script:Other)"
            $v = New-Verifier Off $kh
            $v.AllowChangedKey = $false
            $v.Verify($script:Key) | Should -BeFalse
            $v.Error | Should -BeLike '*Password authentication is disabled*'
        }

        It 'Off tolerates a changed key for key-only authentication, with a warning' {
            $kh = New-KnownHosts "host.example ssh-ed25519 $(ConvertTo-B64 $script:Other)"
            $v = New-Verifier Off $kh
            $v.AllowChangedKey = $true
            $v.Verify($script:Key) | Should -BeTrue
            $v.Warnings.Count | Should -Be 1
            $v.Warnings[0] | Should -BeLike '*HAS CHANGED*'
        }
    }

    Context 'revoked key' {
        It '<Mode> refuses a revoked key' -ForEach @(
            @{ Mode = 'Strict' }, @{ Mode = 'Ask' }, @{ Mode = 'AcceptNew' }, @{ Mode = 'Off' }
        ) {
            $kh = New-KnownHosts @(
                "host.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
                "@revoked host.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
            )
            $v = New-Verifier $Mode $kh
            $v.AllowChangedKey = $true
            $v.Verify($script:Key) | Should -BeFalse
            $v.Error | Should -BeLike '*@revoked*'
        }
    }

    Context 'pinned key (SFTP/SCP connections of an existing session)' {
        It 'accepts only the pinned key' {
            $v = [PwSSH.HostKeyVerifier]::new()
            $v.Mode = [PwSSH.HostKeyMode]::Pinned
            $v.Host = 'host.example'
            $v.PinnedKey = $script:Key
            $v.Verify($script:Key) | Should -BeTrue

            $v2 = [PwSSH.HostKeyVerifier]::new()
            $v2.Mode = [PwSSH.HostKeyMode]::Pinned
            $v2.Host = 'host.example'
            $v2.PinnedKey = $script:Key
            $v2.Verify($script:Other) | Should -BeFalse
            $v2.Error | Should -BeLike '*different host key*'
        }

        It 'refuses everything when no key is pinned' {
            $v = [PwSSH.HostKeyVerifier]::new()
            $v.Mode = [PwSSH.HostKeyMode]::Pinned
            $v.Host = 'host.example'
            $v.Verify($script:Key) | Should -BeFalse
        }
    }

    Context 'capture mode (Get-SSHHostKey)' {
        It 'records the key and never trusts it' {
            $v = [PwSSH.HostKeyVerifier]::new()
            $v.Mode = [PwSSH.HostKeyMode]::Capture
            $v.Verify($script:Key) | Should -BeFalse
            $v.KeyType | Should -Be 'ssh-ed25519'
            $v.Fingerprint | Should -Be (ConvertTo-SSHFingerprint -KeyData $script:Key)
        }
    }

    Context 'event handler' {
        BeforeAll {
            # Stand-in for Renci.SshNet.Common.HostKeyEventArgs: CanTrust defaults to true
            if (-not ('PwsshTest.FakeHostKeyEventArgs' -as [type])) {
                Add-Type -TypeDefinition @'
namespace PwsshTest {
    public class FakeHostKeyEventArgs : System.EventArgs {
        public bool CanTrust { get; set; }
        public byte[] HostKey { get; set; }
        public string HostKeyName { get; set; }
        public int KeyLength { get; set; }
        public FakeHostKeyEventArgs() { CanTrust = true; }
    }
    public class FakeClient {
        public event System.EventHandler<FakeHostKeyEventArgs> HostKeyReceived;
        public bool Raise(byte[] key) {
            var e = new FakeHostKeyEventArgs(); e.HostKey = key; e.HostKeyName = "ssh-ed25519"; e.KeyLength = 256;
            if (HostKeyReceived != null) HostKeyReceived(this, e);
            return e.CanTrust;
        }
        public bool RaiseOnThread(byte[] key) {
            bool result = true;
            var t = new System.Threading.Thread(() => { result = Raise(key); });
            t.Start(); t.Join();
            return result;
        }
    }
}
'@
            }
        }

        It 'sets CanTrust from a thread that has no PowerShell runspace' {
            $kh = New-KnownHosts "host.example ssh-ed25519 $(ConvertTo-B64 $script:Key)"
            $client = [PwsshTest.FakeClient]::new()
            $v = New-Verifier Strict $kh
            $v.Attach($client)
            $client.RaiseOnThread($script:Key) | Should -BeTrue
            $v.Invoked | Should -BeTrue
            $v.KeyLength | Should -Be 256

            $client2 = [PwsshTest.FakeClient]::new()
            $v2 = New-Verifier Strict $kh
            $v2.Attach($client2)
            $client2.RaiseOnThread($script:Other) | Should -BeFalse
        }

        It 'fails closed when verification itself throws' {
            $client = [PwsshTest.FakeClient]::new()
            $v = New-Verifier Strict (Join-Path $script:Dir 'unused')
            $v.Attach($client)
            $client.Raise($null) | Should -BeFalse      # null key -> exception inside the handler
            $v.Trusted | Should -BeFalse
            $v.Error | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'known_hosts cmdlets with OpenSSH syntax' {
    BeforeAll {
        $script:KeyData = New-TestHostKeyData
    }

    It 'Get-SSHKnownHost reports markers, hashing, comments and per-host ports' {
        $hashed = [PwSSH.KnownHostsFile]::HashHost('secret.example')
        $kh = New-KnownHosts @(
            "$hashed ssh-ed25519 $script:KeyData"
            "@revoked * ssh-ed25519 $script:KeyData"
            "[a.example]:2222,[b.example]:2200 ssh-ed25519 $script:KeyData some comment"
        )
        $all = @(Get-SSHKnownHost -Path $kh)
        $all.Count | Should -Be 4
        $all[0].Hashed | Should -BeTrue
        $all[1].Marker | Should -Be '@revoked'
        $all[2].HostName | Should -Be 'a.example'
        $all[2].Port | Should -Be 2222
        $all[3].Port | Should -Be 2200
        $all[3].Comment | Should -Be 'some comment'
        $all | ForEach-Object { $_.Fingerprint | Should -BeLike 'SHA256:*' }
    }

    It 'Get-SSHKnownHost -HostName finds a hashed entry' {
        $hashed = [PwSSH.KnownHostsFile]::HashHost('secret.example')
        $kh = New-KnownHosts "$hashed ssh-ed25519 $script:KeyData"
        @(Get-SSHKnownHost -Path $kh -HostName 'secret.example').Count | Should -Be 1
        @(Get-SSHKnownHost -Path $kh -HostName 'other.example').Count | Should -Be 0
    }

    It 'Add-SSHKnownHost does not add the same entry twice' {
        $kh = Join-Path $script:Dir ("dup_" + [guid]::NewGuid().ToString('N'))
        Add-SSHKnownHost -HostName 'dup.example' -KeyType 'ssh-ed25519' -KeyData $script:KeyData -Path $kh
        Add-SSHKnownHost -HostName 'dup.example' -KeyType 'ssh-ed25519' -KeyData $script:KeyData -Path $kh
        @(Get-Content $kh).Count | Should -Be 1
    }

    It 'Add-SSHKnownHost -HashHostName writes an entry the lookup accepts' {
        $kh = Join-Path $script:Dir ("hash_" + [guid]::NewGuid().ToString('N'))
        Add-SSHKnownHost -HostName 'h.example' -Port 2222 -KeyType 'ssh-ed25519' -KeyData $script:KeyData -Path $kh -HashHostName
        Get-Content $kh | Should -BeLike '|1|*'
        Get-Status $kh 'h.example' 2222 ([Convert]::FromBase64String($script:KeyData)) | Should -Be 'Ok'
    }

    It 'Add-SSHKnownHost rejects <Case>' -ForEach @(
        @{ Case = 'a host name with whitespace'; HostName = "evil`nother ssh-ed25519 AAAA"; KeyType = 'ssh-ed25519' }
        @{ Case = 'a wildcard host name';        HostName = '*';                            KeyType = 'ssh-ed25519' }
        @{ Case = 'a key type with a space';     HostName = 'ok.example';                   KeyType = 'ssh-ed25519 x' }
        @{ Case = 'a mismatched key type';       HostName = 'ok.example';                   KeyType = 'ssh-rsa' }
    ) {
        $kh = Join-Path $script:Dir ("bad_" + [guid]::NewGuid().ToString('N'))
        { Add-SSHKnownHost -HostName $HostName -KeyType $KeyType -KeyData $script:KeyData -Path $kh -ErrorAction Stop } | Should -Throw
        Test-Path $kh | Should -BeFalse
    }

    It 'Add-SSHKnownHost rejects key data that is not base64' {
        $kh = Join-Path $script:Dir ("bad_" + [guid]::NewGuid().ToString('N'))
        { Add-SSHKnownHost -HostName 'ok.example' -KeyType 'ssh-ed25519' -KeyData 'not base64!' -Path $kh -ErrorAction Stop } | Should -Throw
    }

    It 'Remove-SSHKnownHost removes hashed entries and keeps everything else byte for byte' {
        $hashed = [PwSSH.KnownHostsFile]::HashHost('gone.example')
        $kh = New-KnownHosts @(
            '# header comment'
            "$hashed ssh-ed25519 $script:KeyData"
            "keep.example ssh-ed25519 $script:KeyData"
            "@revoked gone.example ssh-ed25519 $script:KeyData"
        )
        Remove-SSHKnownHost -HostName 'gone.example' -Path $kh -Confirm:$false
        [System.IO.File]::ReadAllText($kh) | Should -Be (@(
            '# header comment'
            "keep.example ssh-ed25519 $script:KeyData"
            "@revoked gone.example ssh-ed25519 $script:KeyData"
        ) -join "`n" | ForEach-Object { "$_`n" })
    }

    It 'Remove-SSHKnownHost only removes the requested port' {
        $kh = New-KnownHosts @(
            "p.example ssh-ed25519 $script:KeyData"
            "[p.example]:2222 ssh-ed25519 $script:KeyData"
        )
        Remove-SSHKnownHost -HostName 'p.example' -Port 2222 -Path $kh -Confirm:$false
        @(Get-Content $kh) | Should -Be @("p.example ssh-ed25519 $script:KeyData")
    }

    It 'Remove-SSHKnownHost leaves the file untouched when nothing matches' {
        $kh = New-KnownHosts "keep.example ssh-ed25519 $script:KeyData"
        $before = (Get-Item $kh).LastWriteTimeUtc
        Start-Sleep -Milliseconds 20
        Remove-SSHKnownHost -HostName 'absent.example' -Path $kh -Confirm:$false
        (Get-Item $kh).LastWriteTimeUtc | Should -Be $before
    }

    It 'resolves a relative -Path against the PowerShell location, not the process directory' {
        Push-Location $script:Dir
        try {
            Add-SSHKnownHost -HostName 'rel.example' -KeyType 'ssh-ed25519' -KeyData $script:KeyData -Path 'relative_kh'
            Test-Path (Join-Path $script:Dir 'relative_kh') | Should -BeTrue
            @(Get-SSHKnownHost -Path 'relative_kh').Count | Should -Be 1
        }
        finally { Pop-Location }
    }
}
