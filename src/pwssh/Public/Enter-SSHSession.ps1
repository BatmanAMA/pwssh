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
                    $shell.Write($key.KeyChar.ToString())
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
