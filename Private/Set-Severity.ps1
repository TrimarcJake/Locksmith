function Set-Severity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Issue
    )
    foreach ($Finding in $Issue) {
        try {
            # Auditing
            if ($Finding.Technique -eq 'DETECT') {
                return 'Medium'
            }
            # ESC6
            if ($Finding.Technique -eq 'ESC6') {
                return 'High'
            }
            # ESC8
            if ($Finding.Technique -eq 'ESC8') {
                return 'High'
            }
            # ESC1, ESC2, ESC4, ESC5
            $SID = ConvertFrom-IdentityReference -Object $Finding.IdentityReference
            if ($SID -match $SafeUsers -or $SID -match $SafeOwners) {
                return 'Medium'
            }
            if (($SID -notmatch $SafeUsers -and $SID -notmatch $SafeOwners) -and ($Finding.ActiveDirectoryRights -match $DangerousRights)) {
                return 'Critical'
            }
        } catch {
            Write-Error "Could not determine issue severity for issue: $($Issue.Issue)"
                return 'Unknown Failure'
        }
    }
}
