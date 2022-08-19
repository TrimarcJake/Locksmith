- Display Logo
- Begin gathering data:
  - All objects in the PKS container
  - Membership in the Cert Publishers group
- Check if "Mode" parameter is set at command line:
  - $true: enable desired functionality
  - $false: Display menu
    0. Display all discovered misconfigurations in the console
    1. Write all discovered misconfigurations to CSV files
    2. Write all discovered misconfigurations to CSV files & creates a custom Powershell script to fix them
    3. Write all discovered misconfigurations to CSV files, creates a custom Powershell script to fix them, & attempts to fix all issues

    Results of this menu selection will set the Mode vriable

- Mode 0:
  - $WriteToConsole = $true
  - $WriteToCSV = $false
  - $CreateRemediationScript = $false
  - $ExecuteRemediationScript = $false

- Mode 1:
  - $WriteToConsole = $false
  - $WriteToCSV = $true
  - $CreateRemediationScript = $false
  - $ExecuteRemediationScript = $false

- Mode 2:
  - $WriteToConsole = $false
  - $WriteToCSV = $true
  - $CreateRemediationScript = $true
  - $ExecuteRemediationScript = $false

- Mode 3:
  - $WriteToConsole = $false
  - $WriteToCSV = $true
  - $CreateRemediationScript = $true
  - $ExecuteRemediationScript = $true

function Set-Targets

function Get-ADCSData

function Get-ADCSAuditing

function Find-ESC1

function Find-ESC2

function Find-ESC4

function Find-ESC5

function Find-ESC6

function Repair-ADCSAuditing

function Repair-ESC1

function Repair-ESC2

function Repair-ESC4

function Repair-ESC5

function Repair-ESC6

function Write-Findings





