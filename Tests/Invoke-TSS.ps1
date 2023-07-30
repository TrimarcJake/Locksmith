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
    'ESC1and2AutoEnroll'
    'ESC1and2Enroll'
    'ESC1AutoEnroll'
    'ESC1AutoEnrollFiltered'
    'ESC1Enroll'
    'ESC1EnrollFiltered'
    'ESC2AutoEnroll'
    'ESC2AutoEnrollFiltered'
    'ESC2Enroll'
    'ESC2EnrollFiltered'
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

$ESC1and2AutoEnroll = Get-ADObject "CN=ESC1and2AutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1and2AutoEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
    'pKIExtendedKeyUsage' = '2.5.29.37.0'
} 
Set-ADObject $ESC1and2AutoEnroll.DistinguishedName -Add $ESC1and2AutoEnrollProperties
$ACL = Get-Acl "AD:$ESC1and2AutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1and2AutoEnroll" -AclObject $ACL

$ESC1and2Enroll = Get-ADObject "CN=ESC1and2Enroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1and2EnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
    'pKIExtendedKeyUsage' = '2.5.29.37.0'
} 
Set-ADObject $ESC1and2Enroll.DistinguishedName -Add $ESC1and2EnrollProperties
$ACL = Get-Acl "AD:$ESC1and2Enroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1and2Enroll" -AclObject $ACL

$ESC1AutoEnroll = Get-ADObject "CN=ESC1AutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1AutoEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
    'pKIExtendedKeyUsage' = '1.3.6.1.5.5.7.3.2'
} 
Set-ADObject $ESC1AutoEnroll.DistinguishedName -Add $ESC1AutoEnrollProperties
$ACL = Get-Acl "AD:$ESC1AutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1AutoEnroll" -AclObject $ACL

$ESC1Enroll = Get-ADObject "CN=ESC1Enroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC1EnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
    'pKIExtendedKeyUsage' = '1.3.6.1.5.5.7.3.2'
} 
Set-ADObject $ESC1Enroll.DistinguishedName -Add $ESC1EnrollProperties
$ACL = Get-Acl "AD:$ESC1Enroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC1Enroll" -AclObject $ACL

$ESC2AutoEnroll = Get-ADObject "CN=ESC2AutoEnroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC2AutoEnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
}   
Set-ADObject $ESC2AutoEnroll.DistinguishedName -Add $ESC2AutoEnrollProperties
Set-ADObject $ESC2AutoEnroll.DistinguishedName -Clear pKIExtendedKeyUsage
$ACL = Get-Acl "AD:$ESC2AutoEnroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$AutoEnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC2AutoEnroll" -AclObject $ACL

$ESC2Enroll = Get-ADObject "CN=ESC2Enroll,CN=Certificate Templates,$PKSContainer" -Properties *
$ESC2EnrollProperties = @{
    'msPKI-Certificate-Name-Flag' = 1
    'msPKI-Enrollment-Flag' = 0
}   
Set-ADObject $ESC2Enroll.DistinguishedName -Add $ESC2EnrollProperties
Set-ADObject $ESC2Enroll.DistinguishedName -Clear pKIExtendedKeyUsage
$ACL = Get-Acl "AD:$ESC2Enroll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$DefaultRights,$Allow,$EnrollGUID
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC2Enroll" -AclObject $ACL

$ESC4GenericAll = Get-ADObject "CN=ESC4GenericAll,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4GenericAll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$GenericAll,$Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC4GenericAll" -AclObject $ACL

$ESC4UnsafeOwner = Get-ADObject "CN=ESC4UnsafeOwner,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4UnsafeOwner"
$ACL.SetOwner($AuthenticatedUsers)
Set-Acl "AD:$ESC4UnsafeOwner" -AclObject $ACL

$ESC4WriteProperty = Get-ADObject "CN=ESC4WriteProperty,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4WriteProperty"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$WriteProperty,$Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC4WriteProperty" -AclObject $ACL

$ESC4WriteOwner = Get-ADObject "CN=ESC4WriteOwner,CN=Certificate Templates,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC4WriteOwner"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$WriteOwner,$Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC4WriteOwner" -AclObject $ACL

$ESC5GenericAll = Get-ADObject "CN=ESC5GenericAll,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5GenericAll"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$GenericAll,$Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC5GenericAll" -AclObject $ACL

$ESC5UnsafeOwner = Get-ADObject "CN=ESC5UnsafeOwner,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5UnsafeOwner"
$ACL.SetOwner($AuthenticatedUsers)
Set-Acl "AD:$ESC5UnsafeOwner" -AclObject $ACL

$ESC5WriteProperty = Get-ADObject "CN=ESC5WriteProperty,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5WriteProperty"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$WriteProperty,$Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC5WriteProperty" -AclObject $ACL

$ESC5WriteOwner = Get-ADObject "CN=ESC5WriteOwner,$PKSContainer" -Properties *
$ACL = Get-Acl "AD:$ESC5WriteOwner"
$AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $AuthenticatedUsers,$WriteOwner,$Allow
$ACL.AddAccessRule($AccessRule)
Set-Acl "AD:$ESC5WriteOwner" -AclObject $ACL