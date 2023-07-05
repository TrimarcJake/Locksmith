function Test-IsLocalAccountSession {
    <#
    .SYNOPSIS
        Tests if the current session is running under a local user account or a domain account.
    .DESCRIPTION
        This function returns True if the current session is a local user or False if it is a domain user.
    .EXAMPLE
        Test-IsLocalAccountSession
    .EXAMPLE
        if ( (Test-IsLocalAccountSession) ) { Write-Host "You are running this script under a local account." -ForeGroundColor Yellow }
    #>
    [CmdletBinding()]

    $CurrentSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $LocalSIDs = (Get-LocalUser).SID.Value
    if ($CurrentSID -in $LocalSIDs) {
        Return $true
    }
}
