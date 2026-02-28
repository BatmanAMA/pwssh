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
        $s = switch ($PSCmdlet.ParameterSetName) {
            'ById' {
                Initialize-SSHSessionStore
                if ($script:SSHSessions.ContainsKey($SessionId)) {
                    $script:SSHSessions[$SessionId]
                }
                else {
                    Write-Error "Session $SessionId not found."; return
                }
            }
            'BySession' { $Session }
        }

        if (-not $s.Connected -or -not $s.InternalSession.IsConnected) {
            Write-Error "Session $($s.SessionId) is not connected."
            return
        }

        $cols = if ($Columns -gt 0) { $Columns } elseif ($Host.UI.RawUI.WindowSize.Width) { $Host.UI.RawUI.WindowSize.Width } else { 80 }
        $rows = if ($Rows -gt 0) { $Rows } elseif ($Host.UI.RawUI.WindowSize.Height) { $Host.UI.RawUI.WindowSize.Height } else { 24 }

        $shell = $null
        try {
            $shell = $s.InternalSession.CreateShellStream($TerminalType, [uint32]$cols, [uint32]$rows, [uint32]0, [uint32]0, 4096)

            Write-Host "Interactive SSH session to $($s.ComputerName). Type 'exit' to disconnect." -ForegroundColor Cyan

            $encoding = [System.Text.Encoding]::UTF8
            $buffer = [byte[]]::new(4096)

            while ($s.InternalSession.IsConnected) {
                # Read from remote
                if ($shell.DataAvailable) {
                    $read = $shell.Read()
                    if ($read) { [Console]::Write($read) }
                }

                # Read from local console
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq [ConsoleKey]::C -and $key.Modifiers -band [ConsoleModifiers]::Control) {
                        break
                    }

                    # Map special keys to ANSI escape sequences instead of sending null bytes
                    # Use [char]0x1b instead of `e for PS 5.1 compatibility
                    $esc = [char]0x1b
                    $seq = switch ($key.Key) {
                        ([ConsoleKey]::UpArrow)    { "${esc}[A" }
                        ([ConsoleKey]::DownArrow)  { "${esc}[B" }
                        ([ConsoleKey]::RightArrow) { "${esc}[C" }
                        ([ConsoleKey]::LeftArrow)  { "${esc}[D" }
                        ([ConsoleKey]::Home)        { "${esc}[H" }
                        ([ConsoleKey]::End)         { "${esc}[F" }
                        ([ConsoleKey]::Delete)      { "${esc}[3~" }
                        ([ConsoleKey]::Insert)      { "${esc}[2~" }
                        ([ConsoleKey]::PageUp)      { "${esc}[5~" }
                        ([ConsoleKey]::PageDown)    { "${esc}[6~" }
                        ([ConsoleKey]::F1)          { "${esc}[11~" }
                        ([ConsoleKey]::F2)          { "${esc}[12~" }
                        ([ConsoleKey]::F3)          { "${esc}[13~" }
                        ([ConsoleKey]::F4)          { "${esc}[14~" }
                        ([ConsoleKey]::F5)          { "${esc}[15~" }
                        ([ConsoleKey]::F6)          { "${esc}[17~" }
                        ([ConsoleKey]::F7)          { "${esc}[18~" }
                        ([ConsoleKey]::F8)          { "${esc}[19~" }
                        ([ConsoleKey]::F9)          { "${esc}[20~" }
                        ([ConsoleKey]::F10)         { "${esc}[21~" }
                        ([ConsoleKey]::F11)         { "${esc}[23~" }
                        ([ConsoleKey]::F12)         { "${esc}[24~" }
                        ([ConsoleKey]::Tab)         { "`t" }
                        ([ConsoleKey]::Backspace)   { [char]0x7f }
                        ([ConsoleKey]::Enter)       { "`r" }
                        ([ConsoleKey]::Escape)      { $esc }
                        default {
                            if ($key.KeyChar -ne [char]0) { $key.KeyChar.ToString() } else { $null }
                        }
                    }

                    if ($seq) { $shell.Write($seq) }
                }

                [System.Threading.Thread]::Sleep(10)
            }
        }
        catch {
            Write-Error "Interactive session error: $_"
        }
        finally {
            if ($shell) {
                $shell.Close()
                $shell.Dispose()
            }
            Write-Host "`nSSH session ended." -ForegroundColor Cyan
        }
    }
}
