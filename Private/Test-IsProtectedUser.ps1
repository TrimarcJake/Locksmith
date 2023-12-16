function Test-IsMemberOfProtectedUsers {
<#
    .SYNOPSIS
    Check to see if a user is a member of the Protected Users group.

    .DESCRIPTION
    This function checks to see if a specified user or the current user is a member of the Protected Users group in AD.

    .PARAMETER User
    The user that will be checked for membership in the Protected Users group. This parameter accepts input from the pipeline.

    .EXAMPLE
    This example will check if JaneDoe is a member of the Protected Users group.

        Test-IsMemberOfProtectedUsers -User JaneDoe

    .EXAMPLE
    This example will check if the current user is a member of the Protected Users group.

        Test-IsMemberOfProtectedUsers

    .INPUTS
    Active Directory user object, user SID, SamAccountName, etc

    .OUTPUTS
    Boolean

    .NOTES
    Membership in Active Directory's Protect Users group can have implications for anything that relies on NTLM authentication.

#>

    [CmdletBinding()]
    param (
        # User parameter accepts any input that is valid for Get-ADUser
        [Parameter(
            ValueFromPipeline = $true
        )]
        $User
    )

    Import-Module ActiveDirectory

    # Use the currently logged in user if none is specified
    # Get the user from Active Directory
    if (-not($User)) {
        $CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('\')[-1]
        $CheckUser = Get-ADUser $CurrentUser
    }
    else {
        $CheckUser = Get-ADUser $User
    }

    # Get the Protected Users group by SID instead of by its name to ensure compatibility with any locale or language.
    $DomainSID = (Get-ADDomain).DomainSID.Value
    $ProtectedUsersSID = "$DomainSID-525"

    # Get members of the Protected Users group for the current domain. Recuse in case groups are nested in it.
    $ProtectedUsers = Get-ADGroupMember -Identity $ProtectedUsersSID -Recursive | Select-Object -Unique

    # Check if the current user is in the 'Protected Users' group
    if ($ProtectedUsers -contains $CheckUser) {
        Write-Verbose "$($CheckUser.Name) ($($CheckUser.DistinguishedName)) is a member of the Protected Users group."
        $true
    } else {
        Write-Verbose "$($CheckUser.Name) ($($CheckUser.DistinguishedName)) is not a member of the Protected Users group."
        $false
    }
}
