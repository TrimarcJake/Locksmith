<#
.SYNOPSIS
Finds the most common malconfigurations of Active Directory Certificate Services (AD CS).

.DESCRIPTION
Locksmith uses the Active Directory (DA) Powershell (PS) module to identify 6 misconfigurations
commonly found in Enterprise mode AD CS installations.

.COMPONENT
Locksmith requires the AD PS module to be installed in the scope of the Current User.
If Locksmith does not identify the AD PS module as installed, it will attempt to 
install the module. If module installation does not complete successfully, 
Locksmith will fail.

.PARAMETER Domain
Specifies a single domain to be scanned by Invoke-Locksmith.ps1. Useful in large environments that may
take a while to enumerate.

.PARAMETER InputPath
Specifies an input file containing a list of domains to be checked. Input file should consist of
a domain per line of the input file. If this parameter is not defined at runtime,
Invoke-Locksmith.ps1 will attempt to scan any AD CS installation it can find in the forest.

.PARAMETER Mode
Specifies sets of common configurations.
-Mode 0
Finds and displays any malconfiguration in the console.
Outputs a custom PS object for further processing.
No attempt is made to fix identified issues.
Same as Mode not defined. 

-Mode 1
Finds any malconfigurations and writes them to a series of CSV files.
No attempt is made to fix identified issues.
If OutputPath is not defined, Invoke-Locksmith.ps1 will create its output in the local directory. 

-Mode 2
Finds any malconfigurations and writes them to a series of CSV files.
Creates code snippets to fix each issue and writes them to an environment-specific custom .ps1 file.
No attempt is made to fix identified issues.
If OutputPath is not defined, Invoke-Locksmith.ps1 will create its output in the local directory. 

-Mode 3
Finds any malconfigurations and writes them to a series of CSV files.
Creates code snippets to fix each issue and writes them to an environment-specific custom .ps1 file.
Attempts to fix all identified issues. This mode may require high-privileged access.
If OutputPath is not defined, Invoke-Locksmith.ps1 will create its output in the local directory. 

.PARAMETER OutputPath
Specifies the name and path for the CSV-based output file. If this parameter is not defined at runtime,
Invoke-Locksmith.ps1 will output its results to the console.

.INPUTS
None. You cannot pipe objects to Invoke-Locksmith.ps1.

.OUTPUTS
Output types:
1. Console display of identified issues
2. Custom PS Object containing identified issues
3. CSV for each type of malconfiguration
4. Custom .ps1 to resolve each identified issue

.EXAMPLE
PS> .\Invoke-Locksmith.ps1

Description
-------------------------
Running Invoke-Locksmith.ps1 with no parameters configured will scan any AD CS installation accessible to the user
and output all discovered AD CS issues to the console.

.EXAMPLE
PS> .\Invoke-Locksmith.ps1 -InputPath .\TrustedDomains.txt

Description
-------------------------
Specifying an input file of domains will force Invoke-Locksmith.ps1 to attempt to scan the specific domains
listed in TrustedDomains.txt regardless of permissions or visibility into the forest. Because no Mode is
defined, identified issues will not be written to files.

.EXAMPLE
PS> .\Invoke-Locksmith.ps1 -Mode 1 -OutputPath C:\Users\thanks\Documents

Description
-------------------------
In Mode 1, Locksmith will scan all AD CS installations it can find and write its findings to a series
of CSVs in C:\Users\thanks\Documents.

.EXAMPLE
PS> .\Invoke-Locksmith.ps1 -Mode 2 -Domain it.example.com

Description
-------------------------
In this example, Locksmith will only scan the AD CS installation of it.example.com, regardless of how many
domains it can actually access. All malconfigurations and snippets to fix them will output to the local path.

.EXAMPLE
PS> .\Invoke-Locksmith.ps1 -Mode 3 -OutputPath E:\ADisCheeseSwiss

Description
-------------------------
Mode 3 is the "easy button." Running Locksmith in Mode 3 will identify all malconfigs and output them to CSV
files located in E:\ADisCheeseSwiss. Then it will display the snippets it plans to run and waits for human
interaction to confirm everything looks correct.
#>

[CmdletBinding()]
param (
    [string]$Domain,
    [string]$InputPath,
    [int]$Mode,
    [string]$OutputPath
)

$Logo = "
 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.            
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .--'--''-'-'     \'-' .--'--''-'-'     \'-' .--'--''-'-'
     '--'                  '--'                  '--'            
"
$Logo

# Get domains to analyze
if ($Domain) {
    $AllDomains = $Domain
} elseif ($InputPath) {
    $AllDomains = Get-Content $InputPath
} else {
    $AllDomains = (Get-ADForest).Domains
}

# Set OutputPath if not defined at runtime
if ($OutputPath) {
} else {
    $OutputPath = (Get-Location).Path
}

# Create one output directory per domain
foreach ( $domain in $AllDomains ) {
    $DomainPath = $OutputPath + "`\" + $domain
    New-Item -Path $DomainPath -ItemType Directory -Force
}

# Gather AD CS Objects from Public Key Services Container of each domain.
foreach ( $domain in $AllDomains ) {
    $DomainPath = $OutputPath + "`\" + $Domain
    $ADRoot = ( Get-ADRootDSE -Server $domain ).rootDomainNamingContext
    $OutputFile = $DomainPath + "`\" + $domain + ".xml"
    $AllObjects = Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties * 
    $AllObjects | ForEach-Object {
        $_ | Add-Member -Force -MemberType NoteProperty -Name Owner -Value $_.ntSecurityDescriptor.Owner
        $ACL = $_.ntSecurityDescriptor.Access | ForEach-Object {
            [string]$ACE = "`"$($_.IdentityReference)`",`"$($_.ActiveDirectoryRights)`""
            $ACE
        }
        $_ | Add-Member -Force -MemberType NoteProperty -Name ACL -Value $ACL
    }
    $AllObjects | Export-Clixml $OutputFile
}

