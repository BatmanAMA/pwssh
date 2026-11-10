function Enter-SSHSession {
    <#
    .SYNOPSIS
        Enters an interactive SSH shell session.
    .DESCRIPTION
        Opens an interactive terminal stream to the remote SSH host.
        Type 'exit' or press Ctrl+C to return to the local shell.
    .PARAMETER SessionId
        The session ID to interact with.
    .PARAMETER Session
        An SSHSessionInfo object to interact with.
    .PARAMETER TerminalType
        Terminal type to request. Defaults to 'xterm-256color'.
    .PARAMETER Columns
        Terminal width in columns. Defaults to current console width.
    .PARAMETER Rows
        Terminal height in rows. Defaults to current console height.
    .EXAMPLE
        Enter-SSHSession -SessionId 1
    .EXAMPLE
        $s = New-SSHSession server01 -Credential $cred
        $s | Enter-SSHSession
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'ById')]
        [int]$SessionId,

        [Parameter(Mandatory, ParameterSetName = 'BySession', ValueFromPipeline)]
        [SSHSessionInfo]$Session,

        [Parameter()]
        [string]$TerminalType = 'xterm-256color',

        [Parameter()]
        [int]$Columns = 0,

        [Parameter()]
        [int]$Rows = 0
    )

    process {
        $s = if ($PSCmdlet.ParameterSetName -eq 'ById') { Get-SSHTargetSession -SessionId $SessionId }
             else { Get-SSHTargetSession -Session $Session }
        if (-not $s) { return }

        $autoSize = ($Columns -le 0 -and $Rows -le 0)
        $cols = 80
        $rows = 24
        try {
            $size = $Host.UI.RawUI.WindowSize
            if ($size.Width -gt 0)  { $cols = $size.Width }
            if ($size.Height -gt 0) { $rows = $size.Height }
        }
        catch { $autoSize = $false }
        if ($Columns -gt 0) { $cols = $Columns }
        if ($Rows -gt 0)    { $rows = $Rows }

        if ([Console]::IsInputRedirected) {
            Write-Error 'Enter-SSHSession needs an interactive console (standard input is redirected).'
            return
        }

        $shell = $null
        $savedCtrlC = [Console]::TreatControlCAsInput
        try {
            $shell = $s.InternalSession.CreateShellStream($TerminalType, [uint32]$cols, [uint32]$rows, [uint32]0, [uint32]0, 4096)

            Write-Host "Interactive SSH session to $($s.ComputerName). Type 'exit' to leave; press Enter then ~. to force-disconnect." -ForegroundColor Cyan

            # Ctrl+C belongs to the remote program, exactly as with ssh
            [Console]::TreatControlCAsInput = $true

            $esc = [char]0x1b   # `e is not available in Windows PowerShell 5.1
            $atLineStart = $true
            $pendingTilde = $false
            $lastSizeCheck = [datetime]::UtcNow

            while ($s.InternalSession.IsConnected) {
                $didWork = $false

                # Remote -> local
                if ($shell.DataAvailable) {
                    $read = $shell.Read()
                    if ($read) { [Console]::Write($read); $didWork = $true }
                }
                elseif ([PwSSH.ShellStreamHelper]::IsClosed($shell)) {
                    break   # remote shell exited
                }

                # Local -> remote
                while ([Console]::KeyAvailable) {
                    $didWork = $true
                    $key = [Console]::ReadKey($true)

                    # ssh-style escape: "~." at the start of a line disconnects
                    if ($pendingTilde) {
                        $pendingTilde = $false
                        if ($key.KeyChar -eq '.') { return }
                        $shell.Write('~')
                    }
                    elseif ($atLineStart -and $key.KeyChar -eq '~') {
                        $pendingTilde = $true
                        continue
                    }

                    $seq = switch ($key.Key) {
                        ([ConsoleKey]::UpArrow)    { "${esc}[A" }
                        ([ConsoleKey]::DownArrow)  { "${esc}[B" }
                        ([ConsoleKey]::RightArrow) { "${esc}[C" }
                        ([ConsoleKey]::LeftArrow)  { "${esc}[D" }
                        ([ConsoleKey]::Home)       { "${esc}[H" }
                        ([ConsoleKey]::End)        { "${esc}[F" }
                        ([ConsoleKey]::Delete)     { "${esc}[3~" }
                        ([ConsoleKey]::Insert)     { "${esc}[2~" }
                        ([ConsoleKey]::PageUp)     { "${esc}[5~" }
                        ([ConsoleKey]::PageDown)   { "${esc}[6~" }
                        ([ConsoleKey]::F1)         { "${esc}OP" }
                        ([ConsoleKey]::F2)         { "${esc}OQ" }
                        ([ConsoleKey]::F3)         { "${esc}OR" }
                        ([ConsoleKey]::F4)         { "${esc}OS" }
                        ([ConsoleKey]::F5)         { "${esc}[15~" }
                        ([ConsoleKey]::F6)         { "${esc}[17~" }
                        ([ConsoleKey]::F7)         { "${esc}[18~" }
                        ([ConsoleKey]::F8)         { "${esc}[19~" }
                        ([ConsoleKey]::F9)         { "${esc}[20~" }
                        ([ConsoleKey]::F10)        { "${esc}[21~" }
                        ([ConsoleKey]::F11)        { "${esc}[23~" }
                        ([ConsoleKey]::F12)        { "${esc}[24~" }
                        ([ConsoleKey]::Backspace)  { [string][char]0x7f }
                        ([ConsoleKey]::Enter)      { "`r" }
                        default {
                            # Covers printable characters and control characters
                            # (Ctrl+C = 0x03, Ctrl+D = 0x04, Tab, Escape, ...)
                            if ($key.KeyChar -ne [char]0) { $key.KeyChar.ToString() } else { $null }
                        }
                    }

                    if ($seq) {
                        # Alt+key is sent as ESC-prefixed, as terminals do
                        if (($key.Modifiers -band [ConsoleModifiers]::Alt) -and $seq.Length -eq 1) { $seq = "$esc$seq" }
                        $shell.Write($seq)
                        $atLineStart = ($seq -eq "`r")
                    }
                }
                $shell.Flush()

                # Follow local window size changes (checked a few times per second)
                if ($autoSize -and ([datetime]::UtcNow - $lastSizeCheck).TotalMilliseconds -ge 250) {
                    $lastSizeCheck = [datetime]::UtcNow
                    try {
                        $size = $Host.UI.RawUI.WindowSize
                        if ($size.Width -gt 0 -and $size.Height -gt 0 -and ($size.Width -ne $cols -or $size.Height -ne $rows)) {
                            $cols = $size.Width
                            $rows = $size.Height
                            [void][PwSSH.ShellStreamHelper]::Resize($shell, [uint32]$cols, [uint32]$rows)
                        }
                    }
                    catch { $autoSize = $false }
                }

                if (-not $didWork) { [System.Threading.Thread]::Sleep(10) }
            }
        }
        catch [System.ObjectDisposedException] {
            # The remote shell closed while we were reading or writing: a normal exit
        }
        catch {
            if ($_.Exception.GetBaseException() -isnot [System.ObjectDisposedException]) {
                Write-Error "Interactive session error: $(Get-SSHErrorMessage $_)"
            }
        }
        finally {
            [Console]::TreatControlCAsInput = $savedCtrlC
            if ($shell) {
                try { $shell.Dispose() } catch { }
            }
            Write-Host "`nSSH session ended." -ForegroundColor Cyan
        }
    }
}
