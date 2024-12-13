function Update-ESC1Remediation {
    <#
    .SYNOPSIS
        This function asks the user a set of questions to provide the most appropriate remediation for ESC1 issues.

    .DESCRIPTION
        This function takes a single ESC1 issue as input then asks a series of questions to determine the correct
        remediation.

        Questions:
        1. Does the identified principal need to enroll in this template? [Yes/No/Unsure]
        2. Is this certificate widely used and/or frequently requested? [Yes/No/Unsure]

        Depending on answers to these questions, the Issue and Fix attributes on the Issue object are updated.

        TODO: More questions:
        Should the identified principal be able to request certs that include a SAN or SANs?

    .PARAMETER Issue
        A pscustomobject that includes all pertinent information about the ESC1 issue.

    .OUTPUTS
        This function updates ESC1 remediations customized to the user's needs.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-9$|-526$|-527$|S-1-5-10'
        $ESC1Issues = Find-ESC1 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        foreach ($issue in $ESC1Issues) { Update-ESC1Remediation -Issue $Issue }
    #>
    [CmdletBinding()]
    param(
        $Issue
    )

    $Header = "`n[!] ESC1 Issue detected in $($Issue.Name)"
    Write-Host $Header -ForegroundColor Yellow
    Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
    Write-Host "$($Issue.IdentityReference) can provide a Subject Alternative Name (SAN) while enrolling in this"
    Write-Host "template. Manager approval is not required for a certificate to be issued.`n"
    Write-Host 'To provide the most appropriate remediation for this issue, Locksmith will now ask you a few questions.'

    $Enroll = ''
    do {
        $Enroll = Read-Host "`nDoes $($Issue.IdentityReference) need to Enroll in the $($Issue.Name) template? [y/n/unsure]"
    } while ( ($Enroll -ne 'y') -and ($Enroll -ne 'n') -and ($Enroll -ne 'unsure'))

    if ($Enroll -eq 'y') {
        $Frequent = ''
        do {
            $Frequent = Read-Host "`nIs the $($Issue.Name) certificate frequently requested? [y/n/unsure]"
        } while ( ($Frequent -ne 'y') -and ($Frequent -ne 'n') -and ($Frequent -ne 'unsure'))

        if ($Frequent -ne 'n') {
            $Issue.Fix = @"
# Locksmith cannot currently determine the best remediation course.
# Remediation Options:
# 1. If $($Issue.IdentityReference) is a group, remove its Enroll/AutoEnroll rights and grant those rights
#   to a smaller group or a single user/service account.

# 2. Remove the ability to submit a SAN (aka disable "Supply in the request").
`$Object = `'$($_.DistinguishedName)`'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}

# 3. Enable Manager Approval
`$Object = `'$($_.DistinguishedName)`'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@

            $Issue.Revert = @"
# 1. Replace Enroll/AutoEnroll rights from the smaller group/single user/service account and grant those rights
#   back to $($Issue.IdentityReference).

# 2. Restore the ability to submit a SAN.
`$Object = `'$($_.DistinguishedName)`'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}

# 3. Disable Manager Approval
`$Object = `'$($_.DistinguishedName)`'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
        }
    } elseif ($Enroll -eq 'n') {
        $Issue.Fix = @"
# 1. Open the Certification Templates Console: certtmpl.msc
# 2. Double-click the $($Issue.Name) template to open its Properties page.
# 3. Select the Security tab.
# 4. Select the entry for $($Issue.IdentityReference).
# 5. Uncheck the "Enroll" and/or "Autoenroll" boxes.
# 6. Click OK.
"@

        $Issue.Revert = @"
# 1. Open the Certification Templates Console: certtmpl.msc
# 2. Double-click the $($Issue.Name) template to open its Properties page.
# 3. Select the Security tab.
# 4. Select the entry for $($Issue.IdentityReference).
# 5. Check the "Enroll" and/or "Autoenroll" boxes depending on your specific needs.
# 6. Click OK.
"@
    }
}
