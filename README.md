```
 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.            
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .--'--''-'-'     \'-' .--'--''-'-'     \'-' .--'--''-'-'
     '--'                  '--'                  '--'  
```

A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services

# Examples

## Mode 0 (Default) - Identify Issues and Output to Console
``` powershell
PS> .\Invoke-Locksmith.ps1
```
Running `Invoke-Locksmith.ps1` with no parameters or `-Mode 0` will scan the current forest and output all discovered AD CS issues to the console in **Table** format.

Example Output for Mode 0: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode0.md

## Mode 1 - Identify Issues + Fixes and Output to Console
``` powershell
PS> .\Invoke-Locksmith.ps1 -Mode 1
```
This mode scans the current forest and outputs all discovered AD CS issues and possible fixes to the console in **List** format.

## Mode 2 - Identify Issues and Output to CSV
``` powershell
PS> .\Invoke-Locksmith.ps1 -Mode 2
```
Locksmith Mode 2 scans the current forest and outputs all discovered AD CS issues to ADCSIssues.CSV in the present working directory.

## Mode 3 - Identify Issues + Fixes and Output to CSV
``` powershell
PS> .\Invoke-Locksmith.ps1 -Mode 3
```
In Mode 3, Locksmith scans the current forest and outputs all discovered AD CS issues and example fixes to ADCSRemediation.CSV in the present working directory.

## Mode 4 - Fix All Issues
``` powerShell
PS> .\Invoke-Locksmith.ps1 -Mode 4 
```
Mode 4 is the "easy button." Running Locksmith in Mode 4 will identify all misconfigurations and attempt to fix each issue.
