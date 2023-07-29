<#
  .SYNOPSIS
  Converts a secure Active Directory Certificate Services (AD CS) environment to
  an insecure AD CS environment to the purposes of testing.

  .DESCRIPTION
  TSS reconfigures Certificate Authorities and creates
  users, templates, and objects necessary to test AD CS tools.

  .INPUTS
  None. You can't pipe objects to Invoke-TSS.ps1.

  .OUTPUTS
  None. Invoke-TSS.ps1 doesn't generate any output.
#>

#requires -Modules ActiveDirectory

$NewUsers = @(
    'ESC1'
    'ESC2'
    'ESC4GenericAll'
    'ESC4WriteProperty'
    'ESC4WriteOwner'
    'ESC5GenericAll'
    'ESC5WriteProperty'
    'ESC5WriteOwner'
)

$NewUsers | ForEach-Object {
    New-ADUser $_
}

$ADRoot = (Get-ADRootDSE -Server $forest).defaultNamingContext
Get-ADObject -Identity 'CN=SubCA' -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -Properties *
