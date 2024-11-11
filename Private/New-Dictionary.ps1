<#
.SYNOPSIS
Create a dictionary of the escalation paths and insecure configurations that Locksmith scans for.

.DESCRIPTION
The New-Dictionary function is used to instantiate an array of objects that contain the names, definitions,
descriptions, code used to find, code used to fix, and reference URLs. This is invoked by the module's main function.

.NOTES

    VulnerableConfigurationItem Class Definition:
        Version         Update each time the class definition or the dictionary below is changed.
        Name            The short name of the vulnerable configuration item (VCI).
        Category        The high level category of VCI types, including escalation path, server configuration, GPO setting, etc.
        Subcategory     The subcategory of vulnerable configuration item types.
        Summary         A summary of the vulnerability and how it can be abused.
        FindIt          The name of the function that is used to look for the VCI, stored as an invokable scriptblock.
        FixIt           The name of the function that is used to fix the VCI, stored as an invokable scriptblock.
        ReferenceUrls   An array of URLs that are used as references to learn more about the VCI.
#>

function New-Dictionary {
    class VulnerableConfigurationItem {
        static [string] $Version = '2024.11.03.000'
        [string]$Name
        [ValidateSet('Escalation Path','Server Configuration','GPO Setting')][string]$Category
        [string]$Subcategory
        [string]$Summary
        [scriptblock]$FindIt
        [scriptblock]$FixIt
        [uri[]]$ReferenceUrls
    }

    [VulnerableConfigurationItem[]]$Dictionary = @(
        [VulnerableConfigurationItem]@{
            Name = 'ESC1'
            Category = 'Escalation Path'
            Subcategory = 'Vulnerable Client Authentication Templates'
            Summary = ''
            FindIt =  {Find-ESC1}
            FixIt = {Write-Output "Add code to fix the vulnerable configuration."}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC1'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC2'
            Category = 'Escalation Path'
            Subcategory = 'Vulnerable SubCA/Any Purpose Templates'
            Summary = ''
            FindIt =  {Find-ESC2}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Misconfigured%20Certificate%20Templates%20%E2%80%94%20ESC2'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC3'
            Category = 'Escalation Path'
            Subcategory = 'Vulnerable Enrollment Agent Templates'
            Summary = ''
            FindIt =  {
                Find-ESC3Condition1
                Find-ESC3Condition2
            }
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Enrollment%20Agent%20Templates%20%E2%80%94%20ESC3'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC4';
            Category = 'Escalation Path'
            Subcategory = 'Certificate Templates with Vulnerable Access Controls'
            Summary = ''
            FindIt =  {Find-ESC4}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Template%20Access%20Control%20%E2%80%94%20ESC4'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC5';
            Category = 'Escalation Path'
            Subcategory = 'PKI Objects with Vulnerable Access Control'
            Summary = ''
            FindIt =  {Find-ESC5}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20PKI%20Object%20Access%20Control%20%E2%80%94%20ESC5'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC6'
            Category = 'Escalation Path'
            Subcategory = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
            Summary = ''
            FindIt =  {Find-ESC6}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=EDITF_ATTRIBUTESUBJECTALTNAME2%20%E2%80%94%20ESC6'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC7'
            Category = 'Escalation Path'
            Subcategory = 'Vulnerable Certificate Authority Access Control'
            Summary = ''
            FindIt =  {Write-Output 'We have not created Find-ESC7 yet.'}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=Vulnerable%20Certificate%20Authority%20Access%20Control%20%E2%80%94%20ESC7'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC8'
            Category = 'Escalation Path'
            Subcategory = 'AD CS HTTP Endpoints Vulnerable to NTLM Relay'
            Summary = ''
            FindIt =  {Find-ESC8}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2#:~:text=NTLM%20Relay%20to%20AD%20CS%20HTTP%20Endpoints'
        },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC9'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC9}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        # [VulnerableConfigurationItem]@{
        #     Name = 'ESC10'
        #     Category = 'Escalation Path'
        #     Subcategory = ''
        #     Summary = ''
        #     FindIt =  {Find-ESC10}
        #     FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
        #     ReferenceUrls = ''
        # },
        [VulnerableConfigurationItem]@{
            Name = 'ESC11'
            Category = 'Escalation Path'
            Subcategory = 'IF_ENFORCEENCRYPTICERTREQUEST'
            Summary = ''
            FindIt =  {Find-ESC11}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/'
        },
        [VulnerableConfigurationItem]@{
            Name = 'ESC13'
            Category = 'Escalation Path'
            Subcategory = 'Certificate Template linked to Group'
            Summary = ''
            FindIt =  {Find-ESC13}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = 'https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53'
        },
        [VulnerableConfigurationItem]@{
            Name = 'Auditing'
            Category = 'Server Configuration'
            Subcategory = 'Gaps in auditing on certificate authorities and AD CS objects.'
            Summary = ''
            FindIt =  {Find-AuditingIssue}
            FixIt = {Write-Output 'Add code to fix the vulnerable configuration.'}
            ReferenceUrls = @('https://github.com/TrimarcJake/Locksmith','https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/designing-and-implementing-a-pki-part-i-design-and-planning/ba-p/396953')
        }
    )
    Return $Dictionary
}
