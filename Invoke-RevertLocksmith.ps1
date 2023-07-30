<#
Script to revert changes performed by Locksmith
Created 07/30/2023 08:42:16
#>
certutil -config WIN-SUHK7VS9FN6.foal.horse.local\foal-CA -setreg CA\AuditFilter  Never Configured; Invoke-Command -ComputerName 'WIN-SUHK7VS9FN6.foal.horse.local' -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service -Force }
certutil -config WIN-UHFOTRGHLQ7.horse.local\CA -setreg CA\AuditFilter  0; Invoke-Command -ComputerName 'WIN-UHFOTRGHLQ7.horse.local' -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service -Force }
certutil -config WIN-SUHK7VS9FN6.foal.horse.local\foal-CA -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName "WIN-SUHK7VS9FN6.foal.horse.local" -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service -Force }
certutil -config WIN-UHFOTRGHLQ7.horse.local\CA -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2; Invoke-Command -ComputerName "WIN-UHFOTRGHLQ7.horse.local" -ScriptBlock { Get-Service -Name 'certsvc' | Restart-Service -Force }
