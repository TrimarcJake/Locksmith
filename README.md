```
 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.            
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .--'--''-'-'     \'-' .--'--''-'-'     \'-' .--'--''-'-'
     '--'                  '--'                  '--'  
```

A ~~tiny~~ small tool built to detect and fix common misconfigurations in Active Directory Certificate Services

# Installation
## Script (classic.):
1. Download the latest script version: https://github.com/TrimarcJake/Locksmith/releases/latest/Invoke-Locksmith.zip
2. Extract the downloaded zip file.

## Module (from the PowerShell Gallery, preferred):
1.
```powershell
Install-Module -Name Locksmith -Scope CurrentUser
```

## Module (from here):
1. Download the latest module version (Locksmith-v<YEAR>.<MONTH>.zip): https://github.com/TrimarcJake/Locksmith/releases/latest
2. Extract the downloaded zip file.
3.
```powershell
Import-Module Locksmith.psd1
```

# Examples

## Mode 0 (Default) - Identify Issues and Output to Console
``` powershell
# Module Version
PS> Invoke-Locksmithd

# Script Version
PS> .\Invoke-Locksmith.ps1
```
Running `Invoke-Locksmith.ps1` with no parameters or `-Mode 0` will scan the current forest and output all discovered AD CS issues to the console in **Table** format.

Example Output for Mode 0: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode0.md

## Mode 1 - Identify Issues + Fixes and Output to Console
``` powershell
# Module Version
PS> Invoke-Locksmith -Mode 1

# Script Version
PS> .\Invoke-Locksmith.ps1 -Mode 1
```
This mode scans the current forest and outputs all discovered AD CS issues and possible fixes to the console in **List** format.

Example Output for Mode 1: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode1.md

## Mode 2 - Identify Issues and Output to CSV
``` powershell
# Module Version
PS> Invoke-Locksmith -Mode 2

# Script Version
PS> .\Invoke-Locksmith.ps1 -Mode 2
```
Locksmith Mode 2 scans the current forest and outputs all discovered AD CS issues to ADCSIssues.CSV in the present working directory.

Example Output for Mode 2: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode2.md

## Mode 3 - Identify Issues + Fixes and Output to CSV
``` powershell
# Module Version
PS> Invoke-Locksmith -Mode 3

# Script Version
PS> .\Invoke-Locksmith.ps1 -Mode 3
```
In Mode 3, Locksmith scans the current forest and outputs all discovered AD CS issues and example fixes to ADCSRemediation.CSV in the present working directory.

Example Output for Mode 3: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode3.md

## Mode 4 - Fix All Issues
``` powershell
# Module Version
PS> Invoke-Locksmith -Mode 4

# Script Version
PS> .\Invoke-Locksmith.ps1 -Mode 4 
```
Mode 4 is the "easy button." Running Locksmith in Mode 4 will identify all misconfigurations and offer to fix each issue. If there is any possible operational impact, Locksmith will warn you.

Example Output for Mode 4: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode4.md
