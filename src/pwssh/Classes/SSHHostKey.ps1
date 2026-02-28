class SSHHostKey {
    [string]$ComputerName
    [int]$Port
    [string]$KeyType             # ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256, etc.
    [string]$Fingerprint         # SHA256 fingerprint
    [string]$FingerprintMD5      # MD5 fingerprint (legacy)
    [int]$KeyLength
    [byte[]]$RawKey

    SSHHostKey() {
        $this.Port = 22
    }

    [string] ToString() {
        return "{0} {1} ({2})" -f $this.ComputerName, $this.KeyType, $this.Fingerprint
    }
}
