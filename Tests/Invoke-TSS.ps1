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

$PKSContainer = "CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADRootDSE).defaultNamingContext)"

$NewTemplates | ForEach-Object {
    New-ADObject -Name $_ -Type 'pKICertificateTemplate' -Path "CN=Certificate Templates,$PKSContainer"
}

$NewObjects | ForEach-Object {
    New-ADObject -Name $_ -Type 'container' -Path $PKSContainer
}
