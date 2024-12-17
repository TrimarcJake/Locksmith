function Format-Result {
    <#
    .SYNOPSIS
        Formats the result of an issue for display.

    .DESCRIPTION
        This script formats the result of an issue for display based on the specified mode.

    .PARAMETER Issue
        The issue object containing information about the detected issue.

    .PARAMETER Mode
        The mode to determine the formatting style. Valid values are 0 and 1.

    .EXAMPLE
        Format-Result -Issue $Issue -Mode 0
        Formats the issue result in table format.

    .EXAMPLE
        Format-Result -Issue $Issue -Mode 1
        Formats the issue result in list format.

    .NOTES
        Author: Spencer Alessi
    #>
    [CmdletBinding()]
    param(
        $Issue,
        [Parameter(Mandatory)]
        [int]$Mode
    )

    $IssueTable = @{
        DETECT        = 'Auditing Not Fully Enabled'
        ESC1          = 'ESC1 - Vulnerable Certificate Template - Authentication'
        ESC2          = 'ESC2 - Vulnerable Certificate Template - Subordinate CA'
        ESC3          = 'ESC3 - Vulnerable Certificate Template - Enrollment Agent'
        ESC4          = 'ESC4 - Vulnerable Access Control - Certificate Template'
        ESC5          = 'ESC5 - Vulnerable Access Control - PKI Object'
        ESC6          = 'ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled'
        ESC8          = 'ESC8 - HTTP/S Enrollment Enabled'
        ESC11         = 'ESC11 - IF_ENFORCEENCRYPTICERTREQUEST Flag Disabled'
        ESC13         = 'ESC13 - Vulnerable Certificate Template - Group-Linked'
        'ESC15/EKUwu' = 'ESC15 - Vulnerable Certificate Template - Schema V1'
    }

    $RiskTable = @{
        'Informational' = 'Black, White'
        'Low'           = 'Black, Yellow'
        'Medium'        = 'Black, DarkYellow'
        'High'          = 'Black, Red'
        'Critical'      = 'White, DarkRed'
        'True'          = 'Black, Red'
        # 'False'         = 'Black, Yellow'
    }

    if ($null -ne $Issue) {
        $UniqueIssue = $Issue.Technique | Sort-Object -Unique
        $Title = $($IssueTable[$UniqueIssue])
        Write-Host "$('-'*($($Title.ToString().Length + 10)))" -ForeGroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
        Write-Host "     " -BackgroundColor Magenta -NoNewline
        Write-Host $Title -BackgroundColor Magenta -ForeGroundColor Black -NoNewline
        Write-Host "     " -BackgroundColor Magenta -NoNewline; Write-Host
        Write-Host "$('-'*($($Title.ToString().Length + 10)))" -ForeGroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host


        if ($Mode -eq 0) {
            switch ($UniqueIssue) {
                {$_ -in @('DETECT','ESC6','ESC8','ESC11')} {
                    $Issue |
                        Format-Table Technique, @{l='CA Name';e={$_.Name}}, @{l='Risk';e={$_.RiskName}}, Issue -Wrap |
                        Write-HostColorized -PatternColorMap $RiskTable
                }
                {$_ -in @('ESC1','ESC2','ESC3','ESC4','ESC13','ESC15/EKUwu')} {
                    $Issue |
                        Format-Table Technique, @{l='Template Name';e={$_.Name}}, @{l='Risk';e={$_.RiskName}}, Enabled, Issue -Wrap |
                        Write-HostColorized -PatternColorMap $RiskTable
                }
                'ESC5' {
                    $Issue |
                        Format-Table Technique, @{l='Object Name';e={$_.Name}}, @{l='Risk';e={$_.RiskName}}, Issue -Wrap |
                        Write-HostColorized -PatternColorMap $RiskTable
                }
            }
        } elseif ($Mode -eq 1) {
            # TODO update switches to use ($_ -in $array)
            switch ($UniqueIssue) {
                'DETECT' { $Issue | Format-List Technique, Name, DistinguishedName, Issue, Fix }
                'ESC1' { $Issue | Format-List Technique, Name, DistinguishedName, Enabled, EnabledOn, Issue, Fix }
                'ESC2' { $Issue | Format-List Technique, Name, DistinguishedName, Enabled, EnabledOn, Issue, Fix }
                'ESC3' { $Issue | Format-List Technique, Name, DistinguishedName, Enabled, EnabledOn, Issue, Fix }
                'ESC4' { $Issue | Format-List Technique, Name, DistinguishedName, Enabled, EnabledOn, Issue, Fix }
                'ESC5' { $Issue | Format-List Technique, Name, DistinguishedName, objectClass, Issue, Fix }
                'ESC6' { $Issue | Format-List Technique, Name, DistinguishedName, Issue, Fix }
                'ESC8' { $Issue | Format-List Technique, Name, DistinguishedName, Issue, Fix }
                'ESC11' { $Issue | Format-List Technique, Name, DistinguishedName, Issue, Fix }
                'ESC13' { $Issue | Format-List Technique, Name, DistinguishedName, Enabled, EnabledOn, Issue, Fix }
                'ESC15/EKUwu' { $Issue | Format-List Technique, Name, DistinguishedName, Enabled, EnabledOn, Issue, Fix }
            }
        }
    }
}
