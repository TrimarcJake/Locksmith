<#
.SYNOPSIS
Create a dictionary of the escalation paths and insecure configurations that Locksmith scans for.

.DESCRIPTION
The Create-Dictionary function is used to instantiate an array of objects that contain the names, definitions,
descriptions, code used to find, code used to fix, and reference URLs. This is invoked by the module's main function.
#>

class VulnerableConfig {
    static [string] $Version = '2023.09.28.001'
    [string]$Name
    [string]$Description
    [ValidateSet('Escalation Path','Server Configuration','GPO Setting')]
    [string]$Category
    [scriptblock]$FindIt
    [scriptblock]$FixIt
    [uri]$ReferenceUrl
}

[array]$Dictionary = [VulnerableConfig]::New()
$Dictionary = @(
    [VulnerableConfig]@{
        Name = 'ESC1'
        Description = 'Misconfigured Certificate Templates'
        Category = "Escalation Path"
        FindIt =  {[array]$AuditingIssues = Find-AuditingIssue -ADCSObjects $ADCSObjects}
        FixIt = {Write-Output "Add code to fix the vulnerable configuration."}
        ReferenceUrl = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC1'
    },
    [VulnerableConfig]@{
        Name = 'ESC2';
        Description = 'Misconfigured Certificate Templates'
        Category = "Escalation Path"
        FindIt =  {Find-ESC2}
        FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        ReferenceUrl = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC2'
    },
    [VulnerableConfig]@{
        Name = 'ESC3'
        Description = 'Enrollment Agent Templates'
        Category = "Escalation Path"
        FindIt =  {Find-ESC3}
        FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        ReferenceUrl = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Enrollment%20Agent%20Templates%20%E2%80%94%20ESC3'
    },
    [VulnerableConfig]@{ 
        Name = 'ESC4';
        Description = 'Vulnerable Certificate Template Access Control'
        Category = "Escalation Path"
        FindIt =  {Find-ESC4}
        FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        ReferenceUrl = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Template%20Access%20Control%20%E2%80%94%20ESC4'
    },
    [VulnerableConfig]@{
        Name = 'ESC5';
        Description = 'Vulnerable PKI Object Access Control'
        Category = "Escalation Path"
        FindIt =  {Find-ESC5}
        FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        ReferenceUrl = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20PKI%20Object%20Access%20Control%20%E2%80%94%20ESC5'
    },
    [VulnerableConfig]@{
        Name = 'ESC6'
        Description = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
        Category = "Escalation Path"
        FindIt =  {Find-ESC6}
        FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        ReferenceUrl = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=EDITF_ATTRIBUTESUBJECTALTNAME2%20%E2%80%94%20ESC6'
    },
    [VulnerableConfig]@{
        Name = 'ESC7'
        Description = 'Vulnerable Certificate Authority Access Control'
        Category = "Escalation Path"
        FindIt =  {Find-ESC7}
        FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        ReferenceUrl = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Authority%20Access%20Control%20%E2%80%94%20ESC7'
    },
    [VulnerableConfig]@{
        Name = 'ESC8'
        Description = 'NTLM Relay to AD CS HTTP Endpoints'
        Category = "Escalation Path"
        FindIt =  {Find-ESC8}
        FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        ReferenceUrl = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=NTLM%20Relay%20to%20AD%20CS%20HTTP%20Endpoints'
    },
    [VulnerableConfig]@{
        Name = 'Auditing'
        Description = 'Gaps in auditing on certificate authorities and AD CS objects.'
        Category = "Server Configuration"
        FindIt =  {Find-AuditingIssue}
        FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        ReferenceUrl = ''
    }
)

Return $Dictionary
