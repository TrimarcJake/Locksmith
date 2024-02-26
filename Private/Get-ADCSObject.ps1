function Get-ADCSObject {
    <#
    .SYNOPSIS
        Retrieves Active Directory Certificate Services (AD CS) objects.

    .DESCRIPTION
        This script retrieves AD CS objects from the specified forests.
        It can be used to gather information about Public Key Services in Active Directory.

    .PARAMETER Targets
        Specifies the forest(s) from which to retrieve AD CS objects.

    .PARAMETER Credential
        Specifies the credentials to use for authentication when retrieving ADCS objects.

    .EXAMPLE
        Get-ADCSObject -Targets forest1.lan -Credential $cred
        This example retrieves ADCS objects from forest1.lan using the specified credentials.

    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Targets,
        [System.Management.Automation.PSCredential]$Credential
    )
    foreach ( $forest in $Targets ) {
        if ($Credential){
            $ADRoot = (Get-ADRootDSE -Credential $Credential -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties * -Credential $Credential
        } else {
            $ADRoot = (Get-ADRootDSE -Server $forest).defaultNamingContext
            Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties *
        }
    }
}
