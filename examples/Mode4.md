### Locksmith will prompt you to confirm each remediation action.

```

 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .--'--''-'-'     \'-' .--'--''-'-'     \'-' .--'--''-'-'
     '--'                  '--'                  '--'

Attempting to fully enable AD CS auditing on horse-DC1-CA...
This should have little impact on your environment.

Command(s) to be run:
PS> certutil -config 'DC1.horse.local\horse-DC1-CA' -setreg 'CA\AuditFilter' 127; Invoke-Command -ComputerName 'DC1.horse.local' -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service -Force }

WARNING: If you continue, this script will attempt to fix this issue.

Confirm
Continue with this operation?
[Y] Yes  [A] Yes to All  [H] Halt Command  [S] Suspend  [?] Help (default is "Y"):
```
### Locksmith will warn you if there are possible operational impacts.
```

 _       _____  _______ _     _ _______ _______ _____ _______ _     _
 |      |     | |       |____/  |______ |  |  |   |      |    |_____|
 |_____ |_____| |_____  |    \_ ______| |  |  | __|__    |    |     |
     .--.                  .--.                  .--.
    /.-. '----------.     /.-. '----------.     /.-. '----------.
    \'-' .--'--''-'-'     \'-' .--'--''-'-'     \'-' .--'--''-'-'
     '--'                  '--'                  '--'

Attempting to enable Manager Approval on the ESC1-Vulnerable template...

Command(s) to be run:
PS> Get-ADObject 'CN=ESC1-Vulnerable,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=horse,DC=local' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 0}

WARNING: This could cause some services to stop working until certificates are approved.
If you continue this script will attempt to fix this issues.

Confirm
Continue with this operation?
[Y] Yes  [A] Yes to All  [H] Halt Command  [S] Suspend  [?] Help (default is "Y"):
```

### Example Revert Script for the two examples shown above:
``` powershell
<#
Script to revert changes performed by Locksmith
Created 05/13/2023 09:08:06
#>
certutil -config DC1.horse.local\horse-DC1-CA -setreg CA\AuditFilter  0; Invoke-Command -ComputerName 'DC1.horse.local' -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service -Force }
Get-ADObject 'CN=ESC1-Vulnerable,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=horse,DC=local' | Set-ADObject -Replace @{'msPKI-Certificate-Name-Flag' = 1}
```