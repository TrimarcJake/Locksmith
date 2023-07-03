function Get-ADCSObject {
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