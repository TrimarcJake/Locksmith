```
 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .---'-''-'-'     \'-' .--'--''-'-'     \'-' .--'--'-''-'
     '--'                  '--'                  '--'
```

A ~~tiny~~ small tool built to find and fix common misconfigurations in Active Directory Certificate Services.

<!-- locksmith-badges-start -->
![GitHub release](https://img.shields.io/github/v/release/trimarcjake/locksmith?sort=semver)
![GitHub top language](https://img.shields.io/github/languages/top/trimarcjake/locksmith)
![PowerShell Gallery Platform Support](https://img.shields.io/powershellgallery/p/locksmith)
[![GitHub contributors](https://img.shields.io/github/contributors/trimarcjake/locksmith.svg)](https://github.com/trimarcjake/locksmith/graphs/contributors/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/trimarcjake/Locksmith/powershell.yml?logo=github&label=PSScriptAnalyzer)
![PowerShell Gallery Downloads](https://img.shields.io/powershellgallery/dt/locksmith?logo=powershell&label=PowerShell%20Gallery%20Downloads&color=blue)
[![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Checkout+Locksmith+and+fix+common+misconfigurations+in+Active+Directory+Certificate+Services.&url=https://github.com/trimarcjake/locksmith&hashtags=ADCS,PKI,infosec,powershell)
<!-- locksmith-badges-end -->

# Contents
1. [Installation](#Installation)
2. [Run Locksmith](#RunLocksmith)
   1. [Mode 0](#Mode0)
   2. [Mode 1](#Mode1)
   3. [Mode 2](#Mode2)
   4. [Mode 3](#Mode3)
   5. [Mode 4](#Mode4)
   6. [Scans](#Scans)

# Installation
## Prerequisites
1. Locksmith (both script and module versions) must be run on a domain joined system.
2. Locksmith (module version only) needs the ActiveDirectory and ServerManager PowerShell modules installed.

## Module
### Install module from the PowerShell Gallery (preferred):
1. Open a PowerShell prompt and run `Install-Module -Name Locksmith -Scope CurrentUser`

### Install module manually from GitHub:
1. Download the [latest module version](https://github.com/TrimarcJake/Locksmith/releases/latest) ( **Locksmith-v**\<YEAR\>**.**\<MONTH\>**.zip** )
2. Extract the downloaded zip file
3. Open a PowerShell prompt to the location of the extracted file and run `Import-Module .\Locksmith.psd1`

## Script
### Download the standalone script (classic) without module:
1. Download the latest script version: [https://github.com/TrimarcJake/Locksmith/releases/latest/download/Invoke-Locksmith.zip](https://github.com/TrimarcJake/Locksmith/releases/latest/download/Invoke-Locksmith.zip)
2. Open a PowerShell prompt to the location of the downloaded file and run `.\Invoke-Locksmith.ps1`

<a name="RunLocksmith" id="RunLocksmith"></a>
# Run Locksmith

<a name="Mode0" id="Mode0"></a>
## Mode 0: Identify Issues, Output to Console (Default)
Running `Invoke-Locksmith.ps1` with no parameters or with `-Mode 0` will scan the current Active Directory forest and output all discovered AD CS issues to the console in **Table** format.
``` powershell
# Module Syntax
Invoke-Locksmith
```
``` powershell
# Script Syntax
.\Invoke-Locksmith.ps1
```

Example Output for Mode 0: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode0.md
<br>
<br>
<a name="Mode1" id="Mode1"></a>
## Mode 1:  Identify Issues and Fixes, Output to Console
This mode scans the current forest and outputs all discovered AD CS issues and possible fixes to the console in **List** format.
``` powershell
# Module Syntax
Invoke-Locksmith -Mode 1
```
``` powershell
# Script Syntax
.\Invoke-Locksmith.ps1 -Mode 1
```

Example Output for Mode 1: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode1.md
<br>
<br>
<a name="Mode2" id="Mode2"></a>
## Mode 2:  Identify Issues, Output to CSV
Locksmith Mode 2 scans the current forest and outputs all discovered AD CS issues to ADCSIssues.CSV in the present working directory.
``` powershell
# Module Syntax
Invoke-Locksmith -Mode 2
```
``` powershell
# Script Syntax
.\Invoke-Locksmith.ps1 -Mode 2
```

Example Output for Mode 2: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode2.md
<br>
<br>
<a name="Mode3" id="Mode3"></a>
## Mode 3:  Identify Issues and Fixes, Output to CSV
In Mode 3, Locksmith scans the current forest and outputs all discovered AD CS issues and example fixes to ADCSRemediation.CSV in the present working directory.
``` powershell
# Module Syntax
Invoke-Locksmith -Mode 3
```
``` powershell
# Script Syntax
.\Invoke-Locksmith.ps1 -Mode 3
```

Example Output for Mode 3: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode3.md
<br>
<br>
<a name="Mode4" id="Mode4"></a>
## Mode 4:  Fix All Issues
Mode 4 is the "easy button." Running Locksmith in Mode 4 will identify all misconfigurations and offer to fix each issue. If there is any possible operational impact, Locksmith will warn you.
``` powershell
# Module Syntax
Invoke-Locksmith -Mode 4
```
``` powershell
# Script Syntax
.\Invoke-Locksmith.ps1 -Mode 4
```

Example Output for Mode 4: https://github.com/TrimarcJake/Locksmith/blob/main/examples/Mode4.md
<br>
<br>
<a name="Scans" id="Scans"></a>
## Scans:  Select Which Scans to Run
Use the `-Scans` parameter to choose which vulnerabilities to scan for. Acceptable values include `All`, `Auditing`, `ESC1`, `ESC2`, `ESC3`, `ESC4`, `ESC5`, `ESC6`, `ESC8`, or `PromptMe`. The `PromptMe` option presents an interactive list allowing you to select scans.

``` powershell
# Run all scans
Invoke-Locksmith -Scan All
```

``` powershell
# Prompt the user for a list of scans to select
Invoke-Locksmith.ps1 -Scans PromptMe
```

``` powershell
# Scan for ESC1 vulnerable paths
Invoke-Locksmith.ps1 -Scans ESC1
```

``` powershell
# Scan for ESC1, ESC2, and ESC8 vulnerable paths
Invoke-Locksmith.ps1 -Scans ESC1,ESC2,ESC8
```
