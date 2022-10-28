## Short Term
- [x] Modes 0 & 1: Headers for Console Output
- [x] Mode 4: Display snippet and get confirmation before running.
  - [x] Include details about how changes could affect environment. 
- [x] Add Domain Controllers group, ENTERPRISE DOMAIN CONTROLLERS group, and individual CA Hosts to $SafeUsers
- [x] Add Forest name to "Cert Publishers" and "Administrator" definitions in $SafeOwners and $SafeUsers
- [x] Enumerate users in Domain Admins, Enterprise Admins, Administrators and add them to $SafeUsers
- [x] Update README.md with Examples
- Script to reset any fixed items
- Testing of all modes

## Medium Term
- ESC7 and ESC8 coverage
- Backup before running Mode 4
- Convert $SafeOwners and $SafeUsers to SIDs
- Rename Modes to something that makes sense
- Text-Based User Interface
- Check for Auditing GPOS, Warn if none found
- ACL and Owner remediation snippets
- Improved Error Handling

## Long Term
Check for Elevation before Fixing
Multi-Forest support

## Comment-based Help pulled from original version
```` powershell
<#
.PARAMETER Forest
Specifies a single forest to be scanned by Invoke-Locksmith.ps1. Useful in large environments that may
take a while to enumerate.

.PARAMETER InputPath
Specifies an input file containing a list of forests to be checked. Input file should consist of
a forest per line of the input file. If this parameter is not defined at runtime,
Invoke-Locksmith.ps1 will attempt to scan every AD CS installation it can find in the forest.

.PARAMETER OutputPath
Specifies the name and path for the CSV-based output file. If this parameter is not defined at runtime,
Invoke-Locksmith.ps1 will output its results to the console.

.EXAMPLE
PS> .\Invoke-Locksmith.ps1

Description
-------------------------
Running Invoke-Locksmith.ps1 with no parameters configured will scan any AD CS installation accessible to the user
and output all discovered AD CS issues to the console.

.EXAMPLE
PS> .\Invoke-Locksmith.ps1 -InputPath .\TrustedForests.txt

Description
-------------------------
Specifying an input file of forests will force Invoke-Locksmith.ps1 to attempt to scan the specific forests
listed in TrustedForests.txt regardless of permissions or visibility into the forest. Because no Mode is
defined, identified issues will not be written to files.

.EXAMPLE
PS> .\Invoke-Locksmith.ps1 -Mode 2 -OutputPath C:\Users\thanks\Documents

Description
-------------------------
In Mode 1, Locksmith will scan all AD CS installations it can find and write its findings to a series
of CSVs in C:\Users\thanks\Documents.

.EXAMPLE
PS> .\Invoke-Locksmith.ps1 -Mode 3 -Forest it.example.com

Description
-------------------------
In this example, Locksmith will only scan the AD CS installation of it.example.com, regardless of how many
forests it can actually access. All malconfigurations and snippets to fix them will output to the local path.

.EXAMPLE
PS> .\Invoke-Locksmith.ps1 -Mode 4 -OutputPath E:\ADisCheeseSwiss

Description
-------------------------
Mode 3 is the "easy button." Running Locksmith in Mode 3 will identify all malconfigs and output them to CSV
files located in E:\ADisCheeseSwiss. Then it will display the snippets it plans to run and waits for human
interaction to confirm everything looks correct.
#>
````
