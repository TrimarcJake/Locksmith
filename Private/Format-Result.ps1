function Format-Result {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Issue,
        [Parameter(Mandatory = $true)]
        [int]$Mode
    )

    $IssueTable = @{
        DETECT = 'Auditing Issues'
        ESC1   = 'ESC1 - Misconfigured Certificate Template'
        ESC2   = 'ESC2 - Misconfigured Certificate Template'
        ESC4   = 'ESC4 - Vulnerable Certifcate Template Access Control'
        ESC5   = 'ESC5 - Vulnerable PKI Object Access Control'
        ESC6   = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2'
        ESC8   = 'ESC8 - HTTP Enrollment Enabled'
    }

    if ($null -ne $Issue) {
        $UniqueIssue = $Issue.Technique | Sort-Object -Unique
        Write-Host "`n########## $($IssueTable[$UniqueIssue]) ##########`n"
        switch ($Mode) {
            0 {
                $Issue | Format-Table Technique, Name, Issue, severity -Wrap
            }
            1 {
                if ($Issue.Technique -eq 'ESC8') {
                    $Issue | Format-List Technique, Name, DistinguishedName, CAEnrollmentEndpoint, Issue, Fix, severity
                } else {
                    $Issue | Format-List Technique, Name, DistinguishedName, Issue, Fix, severity
                    if(($Issue.Technique -eq "DETECT" -or $Issue.Technique -eq "ESC6") -and (Get-RestrictedAdminModeSetting)){
                        Write-Warning "Restricted Admin Mode appears to be configured. Certutil.exe may not work from this host, therefore you may need to execute the 'Fix' commands on the CA server itself"
                    }
                }
            }
        }
    }
}