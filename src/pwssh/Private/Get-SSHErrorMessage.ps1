function Get-SSHErrorMessage {
    <#
    .SYNOPSIS
        Returns the innermost exception message of an error record, without the
        'Exception calling "X" with "N" argument(s)' wrapper PowerShell adds.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    if ($ex.Message) { return $ex.Message }
    return "$ErrorRecord"
}
