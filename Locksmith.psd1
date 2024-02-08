@{
    AliasesToExport      = @('*')
    Author               = 'Jake Hildreth'
    CmdletsToExport      = @()
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2022 - 2024. All rights reserved.'
    Description          = 'A small tool to find and fix common misconfigurations in Active Directory Certificate Services.'
    FunctionsToExport    = @('*')
    GUID                 = 'b1325b42-8dc4-4f17-aa1f-dcb5984ca14a'
    ModuleVersion        = '2024.1'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
            IconUri                    = 'https://github.com/TrimarcJake/Locksmith/Images/locksmith.ico'
            ProjectUri                 = 'https://github.com/TrimarcJake/Locksmith'
            Tags                       = @('Windows', 'Locksmith', 'CA', 'PKI', 'ActiveDirectory', 'CertificateServices', 'ADCS')
        }
    }
    RequiredModules      = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
    RootModule           = 'Locksmith.psm1'
}