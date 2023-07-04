function Get-CAHostObject {
    [CmdletBinding()]
    param (
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [array]$ADCSObjects,
        [System.Management.Automation.PSCredential]$Credential
    )
    process {
        if ($Credential) {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                Get-ADObject $_.CAHostDistinguishedName -Properties * -Server $ForestGC -Credential $Credential
            }
        } else {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                Get-ADObject $_.CAHostDistinguishedName -Properties * -Server $ForestGC
            }
        }
    }
}