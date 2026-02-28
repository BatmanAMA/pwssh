class SSHKnownHost {
    [string]$HostName
    [int]$Port
    [string]$KeyType
    [string]$KeyData             # Base64-encoded public key
    [string]$Fingerprint
    [string]$Source              # File path this entry came from
    [int]$LineNumber

    SSHKnownHost() {
        $this.Port = 22
    }

    [string] ToKnownHostsLine() {
        $hostEntry = if ($this.Port -eq 22) { $this.HostName } else { "[{0}]:{1}" -f $this.HostName, $this.Port }
        return "{0} {1} {2}" -f $hostEntry, $this.KeyType, $this.KeyData
    }

    [string] ToString() {
        return "{0} {1}" -f $this.HostName, $this.KeyType
    }
}
