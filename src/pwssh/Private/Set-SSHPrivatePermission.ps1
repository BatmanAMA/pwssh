function Set-SSHPrivatePermission {
    <#
    .SYNOPSIS
        Restricts a file or directory to the current user (0600/0700, or an
        owner-only ACL on Windows).
    .DESCRIPTION
        Throws if the permissions cannot be applied, so callers never leave private
        key material behind with looser permissions than intended.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath
    )

    $isDir = Test-Path -LiteralPath $LiteralPath -PathType Container

    if (Test-SSHIsWindows) {
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $grant = if ($isDir) { "*${sid}:(OI)(CI)F" } else { "*${sid}:F" }
        $out = & icacls.exe $LiteralPath /inheritance:r /grant:r $grant 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to restrict permissions on '$LiteralPath': $out"
        }
    }
    else {
        $mode = if ($isDir) { '700' } else { '600' }
        $out = & chmod $mode $LiteralPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to restrict permissions on '$LiteralPath': $out"
        }
    }
}
