function Format-Result {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Issue,
        [Parameter(Mandatory = $true)]
        [int]$Mode
    )

    $IssueTable = @{
        DETECT = 'Auditing Not Fully Enabled'
        ESC1   = 'ESC1 - Vulnerable Certificate Template - Authentication'
        ESC2   = 'ESC2 - Vulnerable Certificate Template - Subordinate CA'
        ESC3   = 'ESC3 - Vulnerable Certificate Template - Enrollment Agent'
        ESC4   = 'ESC4 - Vulnerable Access Control - Certifcate Template'
        ESC5   = 'ESC5 - Vulnerable Access Control - PKI Object'
        ESC6   = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled'
        ESC8   = 'ESC8 - HTTP/S Enrollment Enabled'
    }

    if ($null -ne $Issue) {
        $UniqueIssue = $Issue.Technique | Sort-Object -Unique
        Write-Host "`n########## $($IssueTable[$UniqueIssue]) ##########`n"
        switch ($Mode) {
            0 {
                $Issue | Format-Table Technique, Name, Issue -Wrap
            }
            1 {
                if ($Issue.Technique -eq 'ESC8') {
                    $Issue | Format-List Technique, Name, DistinguishedName, CAEnrollmentEndpoint, Issue, Fix
                } else {
                    $Issue | Format-List Technique, Name, DistinguishedName, Issue, Fix
                    if(($Issue.Technique -eq "DETECT" -or $Issue.Technique -eq "ESC6") -and (Get-RestrictedAdminModeSetting)){
                        Write-Warning "Restricted Admin Mode appears to be configured. Certutil.exe may not work from this host, therefore you may need to execute the 'Fix' commands on the CA server itself"
                    }
                }
            }
        }
    }
}