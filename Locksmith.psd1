@{
    AliasesToExport      = @('*')
    Author               = 'Jake Hildreth'
    CmdletsToExport      = @()
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2022 - 2023. All rights reserved.'
    Description          = 'A small tool to find and fix common misconfigurations in Active Directory Certificate Services.'
    FunctionsToExport    = @('*')
    GUID                 = 'b1325b42-8dc4-4f17-aa1f-dcb5984ca14a'
    ModuleVersion        = '2023.12'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            Tags                       = @('Windows', 'Locksmith', 'CA', 'PKI', 'ActiveDirectory', 'CertificateServices', 'ADCS')
            ProjectUri                 = 'https://github.com/TrimarcJake/Locksmith'
            ExternalModuleDependencies = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
        }
    }
    RequiredModules      = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
    RootModule           = 'Locksmith.psm1'
}