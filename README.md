# Locksmith
A tool to identify and remediate common misconfigurations in Active Directory Certificate Services

# Examples

## Mode 0 - Default
```PowerShell
PS> .\Invoke-Locksmith.ps1
```
Running `Invoke-Locksmith.ps1` with no parameters configured will scan **any AD CS installation accessible to the user** and output all discovered AD CS issues to the console.

## Mode 1 - Run with a file containing a list of forests
```PowerShell
PS> .\Invoke-Locksmith.ps1 -Mode 1 -InputPath .\TrustedForests.txt
```
Specifying an input file of forests will force `Invoke-Locksmith.ps1` to attempt to scan the specific forests listed in TrustedForests.txt regardless of permissions or visibility into the forest. Because Mode 1 is specified, identified issues and their fix will output to the console.

## Mode 2 - Run with a file containing a list of forests
```PowerShell
PS> .\Invoke-Locksmith.ps1 -Mode 2 -OutputPath C:\Users\thanks\Documents
```
In Mode 2, Locksmith will scan all AD CS installations it can find and write its findings to a series of CSVs in `C:\Users\thanks\Documents`.

## Mode 3 - Run by specifying a single forest
```PowerShell
PS> .\Invoke-Locksmith.ps1 -Mode 3 -Forest it.example.com
```
In this example, Locksmith will only scan the AD CS installation of `it.example.com`, regardless of how many forests it can actually access. All malconfigurations and snippets to fix them will output to the local path.

## Mode 4 - Find and fix all identified issues
```PowerShell
PS> .\Invoke-Locksmith.ps1 -Mode 4 -OutputPath E:\ADisCheeseSwiss
```
Mode 4 is the "easy button." Running Locksmith in Mode 4 will identify all malconfigs and output them to CSV files located in `E:\ADisCheeseSwiss`. Then it will display the snippets it plans to run and waits for human interaction to confirm everything looks correct.