function Invoke-Scans {
    <#
    .SYNOPSIS
        Invoke-Scans.ps1 is a script that performs various scans on ADCS (Active Directory Certificate Services) objects.

    .PARAMETER Scans
        Specifies the type of scans to perform. Multiple scan options can be provided as an array. The default value is 'All'.
        The available scan options are: 'Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'ESC11', 'ESC13', 'All', 'PromptMe'.

    .NOTES
        - The script requires the following functions to be defined: Find-AuditingIssue, Find-ESC1, Find-ESC2, Find-ESC3Condition1,
          Find-ESC3Condition2, Find-ESC4, Find-ESC5, Find-ESC6, Find-ESC8, Find-ESC11, Find-ESC13
        - The script uses Out-GridView or Out-ConsoleGridView for interactive selection when the 'PromptMe' scan option is chosen.
        - The script returns a hash table containing the results of the scans.

    .EXAMPLE
    Invoke-Scans
    # Perform all scans

    .EXAMPLE
    Invoke-Scans -Scans 'Auditing', 'ESC1'
    # Perform only the 'Auditing' and 'ESC1' scans

    .EXAMPLE
    Invoke-Scans -Scans 'PromptMe'
    # Prompt the user to select the scans to perform
    #>

    [CmdletBinding()]
    [OutputType([hashtable])]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', 'Invoke-Scans', Justification = 'Performing multiple scans.')]
    param (
        # Could split Scans and PromptMe into separate parameter sets.
        [Parameter()]
        $ClientAuthEkus,
        $DangerousRights,
        $EnrollmentAgentEKU,
        [int]$Mode,
        $SafeObjectTypes,
        $SafeOwners,
        [ValidateSet('Auditing', 'ESC1', 'ESC2', 'ESC3', 'ESC4', 'ESC5', 'ESC6', 'ESC8', 'ESC11', 'ESC13', 'All', 'PromptMe')]
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
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-ConsoleGridView -OutputMode Multiple -Title $GridViewTitle).Name | Sort-Object -Property Name
        } elseif (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
            [array]$Scans = ($Dictionary | Select-Object Name, Category, Subcategory | Out-GridView -PassThru -Title $GridViewTitle).Name | Sort-Object -Property Name
        } else {
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
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus
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
            Write-Host 'Identifying AD CS templates with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes
        }
        ESC5 {
            Write-Host 'Identifying AD CS objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes
        }
        ESC6 {
            Write-Host 'Identifying Issuing CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
        }
        ESC8 {
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
        }
        ESC11 {
            Write-Host 'Identifying Issuing CAs with IF_ENFORCEENCRYPTICERTREQUEST disabled (ESC11)...'
            [array]$ESC11 = Find-ESC11 -ADCSObjects $ADCSObjects
        }
        ESC13 {
            Write-Host 'Identifying AD CS templates with dangerous ESC13 configurations...'
            [array]$ESC11 = Find-ESC13 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEKUs
        }
        All {
            Write-Host 'Identifying auditing issues...'
            [array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects
            Write-Host 'Identifying AD CS templates with dangerous ESC1 configurations...'
            [array]$ESC1 = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus
            Write-Host 'Identifying AD CS templates with dangerous ESC2 configurations...'
            [array]$ESC2 = Find-ESC2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS templates with dangerous ESC3 configurations...'
            [array]$ESC3 = Find-ESC3Condition1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            [array]$ESC3 += Find-ESC3Condition2 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
            Write-Host 'Identifying AD CS templates with poor access control (ESC4)...'
            [array]$ESC4 = Find-ESC4 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes -Mode $Mode
            Write-Host 'Identifying AD CS objects with poor access control (ESC5)...'
            [array]$ESC5 = Find-ESC5 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeObjectTypes $SafeObjectTypes
            Write-Host 'Identifying Certificate Authorities with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled v (ESC6)...'
            [array]$ESC6 = Find-ESC6 -ADCSObjects $ADCSObjects
            Write-Host 'Identifying HTTP-based certificate enrollment interfaces (ESC8)...'
            [array]$ESC8 = Find-ESC8 -ADCSObjects $ADCSObjects
            Write-Host 'Identifying Certificate Authorities with IF_ENFORCEENCRYPTICERTREQUEST disabled (ESC11)...'
            [array]$ESC11 = Find-ESC11 -ADCSObjects $ADCSObjects
            Write-Host 'Identifying AD CS templates with dangerous ESC13 configurations...'
            [array]$ESC13 = Find-ESC13 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers -ClientAuthEKUs $ClientAuthEkus
            Write-Host
        }
    }

    [array]$AllIssues = $AuditingIssues + $ESC1 + $ESC2 + $ESC3 + $ESC4 + $ESC5 + $ESC6 + $ESC8 + $ESC11 + $ESC13

    # If these are all empty = no issues found, exit
    if ($AllIssues.Count -lt 1) {
        Write-Host "`n$(Get-Date) : No ADCS issues were found." -ForegroundColor Green
        break
    }

    # Return a hash table of array names (keys) and arrays (values) so they can be directly referenced with other functions
    Return @{
        AllIssues      = $AllIssues
        AuditingIssues = $AuditingIssues
        ESC1           = $ESC1
        ESC2           = $ESC2
        ESC3           = $ESC3
        ESC4           = $ESC4
        ESC5           = $ESC5
        ESC6           = $ESC6
        ESC8           = $ESC8
        ESC11          = $ESC11
        ESC13          = $ESC13
    }
}
