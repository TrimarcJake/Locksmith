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

$NewTemplates = @(
    'ESC1'
    'ESC1and2'
    'ESC1Filtered'
    'ESC2'
    'ESC2Filtered'
    'ESC4FilteredEnroll'
    'ESC4FilteredAutoEnroll'
    'ESC4FilteredOwner'
    'ESC4FilteredSafeUsers'
    'ESC4GenericAll'
    'ESC4UnsafeOwner'
    'ESC4WriteProperty'
    'ESC4WriteOwner'    
)

$NewObjects = @(
    'ESC5FilteredEnroll'
    'ESC5FilteredAutoEnroll'
    'ESC5FilteredOwner'
    'ESC5FilteredSafeUsers'
    'ESC5GenericAll'
    'ESC5UnsafeOwner'
    'ESC5WriteProperty'
    'ESC5WriteOwner'
)

$Administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$AuthenticatedUsers = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')

$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$GenericAll = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
$GenericRead = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
$ReadProperty = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
$WriteOwner = [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner
$WriteProperty = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty

$DefaultRights = $ExtendedRight + $GenericRead + $ReadProperty + $WriteProperty

$EnrollGUID = [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$AutoEnrollGUID = [GUID]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

$Allow = [System.Security.AccessControl.AccessControlType]::Allow

$PKSContainer = "CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADRootDSE).defaultNamingContext)"

$NewTemplates | ForEach-Object {
    New-ADObject -Name $_ -Type 'pKICertificateTemplate' -Path "CN=Certificate Templates,$PKSContainer"
}

$NewObjects | ForEach-Object {
    New-ADObject -Name $_ -Type 'container' -Path $PKSContainer
}

$ESC1 = Get-ADObject "CN=ESC1,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1Properties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
    'pKIExtendedKeyUsage' = '1.3.6.1.5.5.7.3.2'
} 
Set-ADObject $ESC1.DistinguishedName -Add $ESC1Properties
$ACL = Get-Acl "AD:$ESC1"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1" -AclObject $ACL

$ESC1and2 = Get-ADObject "CN=ESC1and2,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1and2Properties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
    'pKIExtendedKeyUsage' = '2.5.29.37.0'
} 
Set-ADObject $ESC1and2.DistinguishedName -Add $ESC1and2Properties
$ACL = Get-Acl "AD:$ESC1and2"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1and2" -AclObject $ACL

$ESC2 = Get-ADObject "CN=ESC2,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC2Properties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
    'pKIExtendedKeyUsage' = '2.5.29.37.0'
}   
Set-ADObject $ESC2.DistinguishedName -Add $ESC2Properties
Set-ADObject $ESC2.DistinguishedName -Clear pKIExtendedKeyUsage
$ACL = Get-Acl "AD:$ESC2"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC2" -AclObject $ACL