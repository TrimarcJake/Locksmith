@{
    AliasesToExport      = @('*')
    Author               = 'Jake Hildreth'
    CmdletsToExport      = @()
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2022 - 2023. All rights reserved.'
    Description          = 'A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services.'
    FunctionsToExport    = @('*')
    GUID                 = 'b1325b42-8dc4-4f17-aa1f-dcb5984ca14a'
    ModuleVersion        = '2023.9'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
            Tags                       = @('Windows', 'Locksmith', 'CA', 'PKI', 'ActiveDirectory', 'CertificateServices', 'ADCS')
        }
    }
    RequiredModules      = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
    RootModule           = 'Locksmith.psm1'
}