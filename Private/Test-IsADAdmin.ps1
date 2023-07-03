function Test-IsADAdmin {
    <#
    .SYNOPSIS
        Tests if the current user has administrative rights in Active Directory.
    .DESCRIPTION
        This function returns True if the current user is a Domain Admin (or equivalent) or False if not.
    .EXAMPLE
        Test-IsADAdmin
    .EXAMPLE
        if (!(Test-IsADAdmin)) { Write-Host "You are not running with Domain Admin rights and will not be able to make certain changes." -ForeGroundColor Yellow }
    #>
    if (
        # Need to test to make sure this checks domain groups and not local groups, particularly for 'Administrators' (reference SID instead of name?).
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Domain Admin") -or
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators") -or
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Enterprise Admins")
       ) {
        Return $true
    }
    else {
        Return $false
    }
}
