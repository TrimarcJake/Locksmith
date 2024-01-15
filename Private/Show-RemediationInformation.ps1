function Show-RemediationInformation {
    <#
    .SYNOPSIS
    Shows all important information about a remediation.

    .PARAMETER Thing
    Unsure yet

    #>

    [CmdletBinding()]
    param (
        $IssueObject
    )


    Write-Host 'ISSUE:' -ForegroundColor White
    Write-Host "Auditing is not fully enabled on Certification Authority `"$($_.Name)`".`n"
    Write-Host 'TECHNIQUE:' -ForegroundColor White
    Write-Host "$($_.Technique)`n"
    Write-Host 'ACTION TO BE PERFORMED:' -ForegroundColor White
    Write-Host "Locksmith will attempt to fully enable auditing on Certification Authority `"$($_.Name)`".`n"
    Write-Host 'COMMAND(S) TO BE RUN:'
    Write-Host 'PS> ' -NoNewline
    Write-Host "$($_.Fix)`n" -ForegroundColor Cyan
    Write-Host 'OPERATIONAL IMPACT:' -ForegroundColor White
    Write-Host "This change should have little to no impact on the AD CS environment.`n" -ForegroundColor Green
    Write-Host "If you continue, Locksmith will attempt to fix this issue.`n" -ForegroundColor Yellow

}
