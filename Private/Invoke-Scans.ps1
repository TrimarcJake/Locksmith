function Invoke-Scans {
    <#
    .SYNOPSIS
        Invoke-Scans.ps1 is a script that performs various scans on ADCS (Active Directory Certificate Services) objects.

    .DESCRIPTION
        This script accepts a parameter named $Scans, which specifies the type of scans to perform. The available scan options are:
        - Auditing
        - ESC1
        - ESC2
        - ESC3
        - ESC4
        - ESC5
        - ESC6
        - ESC8
        - All
        - PromptMe

    .PARAMETER Scans
        Specifies the type of scans to perform. Multiple scan options can be provided as an array. The default value is 'All'.
        The available scan options are: 'Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'All', 'PromptMe'.

    .NOTES
        - The script requires the following functions to be defined: Find-AuditingIssue, Find-ESC1, Find-ESC2, Find-ESC3Condition1,
          Find-ESC3Condition2, Find-ESC4, Find-ESC5, Find-ESC6, Find-ESC8.
        - The script uses Out-GridView or Out-ConsoleGridView for interactive selection when the 'PromptMe' scan option is chosen.
        - The script returns a hash table containing the results of the scans.

    .EXAMPLE
        # Perform all scans
        Invoke-Scans 

    .EXAMPLE
        # Perform only the 'Auditing' and 'ESC1' scans
        Invoke-Scans -Scans 'Auditing', 'ESC1'

    .EXAMPLE
        # Prompt the user to select the scans to perform
        Invoke-Scans -Scans 'PromptMe'
    #>

    [CmdletBinding()]
    param (
    # Could split Scans and PromptMe into separate parameter sets.
    [Parameter()]
        $ClientAuthEkus,
        $DangerousRights,
        $EnrollmentAgentEKU,
        [int]$Mode,
        $SafeObjectTypes,
        $SafeOwners,
        [ValidateSet('Auditing','ESC1','ESC2','ESC3','ESC4','ESC5','ESC6','ESC8','All','PromptMe')]
        [array]$Scans = 'All',
        $UnsafeOwners,
        $UnsafeUsers,
        $PreferredOwner
    )

    # Is this needed?
    if ($Scans -eq $IsNullOrEmpty) {
        $Scans = 'All'
    }

    if ( $Scans -eq 'PromptMe' ) {
        $GridViewTitle = 'Select the tests to run and press Enter or click OK to continue...'

        # Check for Out-GridView or Out-ConsoleGridView
        if ((Get-Command Out-ConsoleGridView -ErrorAction SilentlyContinue) -and ($PSVersionTable.PSVersion.Major -ge 7)) {
            [array]$Scans = ($Dictionary | Select-Object Name,Category,Subcategory | Out-ConsoleGridView -OutputMode Multiple -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        elseif (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
            [array]$Scans = ($Dictionary | Select-Object Name,Category,Subcategory | Out-GridView -PassThru -Title $GridViewTitle).Name | Sort-Object -Property Name
        }
        else {
            # To Do: Check for admin and prompt to install features/modules or revert to 'All'.
            Write-Information "Out-GridView and Out-ConsoleGridView were not found on your system. Defaulting to `'All`'."
            $Scans = 'All'
        }
    }

    switch ( $Scans ) {
        Auditing {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
        }
        ESC1 {
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC2 {
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC3 {
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        }
        ESC4 {
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes
        }
        ESC5 {
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes
        }
        ESC6 {
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
        }
        ESC8 {
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
        }
        All {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -Mode $Mode
            Write-Host 'Identifying AD CS template and other objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes
            Write-Host 'Identifying Certificate Authorities configured with dangerous flags (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
        }
    }

    [array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC8

    # If these are all empty = no issues found, exit
    if ((!$AuditingIssues) -and (!$ESC1) -and (!$ESC2) -and (!$ESC3) -and (!$ESC4) -and (!$ESC5) -and (!$ESC6) -and (!$ESC8) ) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found." -ForegroundColor Green
        break
    }

    # Return a hash table of array names (keys) and arrays (values) so they can be directly referenced with other functions
    Return @{
        AllIssues = $AllIssues
        AuditingIssues = $AuditingIssues
        ESC1 = $ESC1
        ESC2 = $ESC2
        ESC3 = $ESC3
        ESC4 = $ESC4
        ESC5 = $ESC5
        ESC6 = $ESC6
        ESC8 = $ESC8
    }
}
