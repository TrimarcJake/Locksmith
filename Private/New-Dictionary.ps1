<#
.SYNOPSIS
Create a dictionary of the escalation paths and insecure configurations that Locksmith scans for.

.DESCRIPTION
The Create-Dictionary function is used to instantiate an array of objects that contain the names, definitions,
descriptions, code used to find, code used to fix, and reference URLs. This is invoked by the module's main function.
#>

function Create-Dictionary {
    class VulnerableConfigurationItem {
        static [string] $Version = '2023.09.28.001'
        [string]$Name
        [string]$Type
        [ValidateSet('Escalation Path','Server Configuration','GPO Setting')][string]$Category
        [scriptblock]$FindIt
        [scriptblock]$FixIt
        [uri[]]$ReferenceUrls
    }

    [array]$Dictionary = [VulnerableConfigurationItem]::New()
    $Dictionary = @(
        [VulnerableConfigurationItem]@{
            Name = 'ESC1'
            Type = 'Misconfigured Certificate Templates'
            Category = "Escalation Path"
            FindIt =  {Find-AuditingIssue}
            FixIt = {Write-Output "Add code to fix the vulnerable configuration."}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC1'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC2';
            Type = 'Misconfigured Certificate Templates'
            Category = "Escalation Path"
            FindIt =  {Find-ESC2}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC2'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC3'
            Type = 'Enrollment Agent Templates'
            Category = "Escalation Path"
            FindIt =  {Find-ESC3}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Enrollment%20Agent%20Templates%20%E2%80%94%20ESC3'
        },
        [VulnerableConfigurationItem]@{ 
            Name = 'ESC4';
            Type = 'Vulnerable Certificate Template Access Control'
            Category = "Escalation Path"
            FindIt =  {Find-ESC4}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Template%20Access%20Control%20%E2%80%94%20ESC4'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC5';
            Type = 'Vulnerable PKI Object Access Control'
            Category = "Escalation Path"
            FindIt =  {Find-ESC5}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20PKI%20Object%20Access%20Control%20%E2%80%94%20ESC5'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC6'
            Type = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
            Category = "Escalation Path"
            FindIt =  {Find-ESC6}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=EDITF_ATTRIBUTESUBJECTALTNAME2%20%E2%80%94%20ESC6'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC7'
            Type = 'Vulnerable Certificate Authority Access Control'
            Category = "Escalation Path"
            FindIt =  {Find-ESC7}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Authority%20Access%20Control%20%E2%80%94%20ESC7'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC8'
            Type = 'NTLM Relay to AD CS HTTP Endpoints'
            Category = "Escalation Path"
            FindIt =  {Find-ESC8}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=NTLM%20Relay%20to%20AD%20CS%20HTTP%20Endpoints'
        },
        [VulnerableConfigurationItem]@{
            Name = 'Auditing'
            Type = 'Gaps in auditing on certificate authorities and AD CS objects.'
            Category = "Server Configuration"
            FindIt =  {Find-AuditingIssue}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = @('https://github.com/TrimarcJake/Locksmith','https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/designing-and-implementing-a-pki-part-i-design-and-planning/ba-p/396953')
        }
    )
}