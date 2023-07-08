@{
    AliasesToExport      = @('*')
    Author               = 'Jake Hildreth'
    CmdletsToExport      = @()
    CompanyName          = 'Trimarc'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2022 - 2023 Author @ Trimarc. All rights reserved.'
    Description          = 'A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services.'
    FunctionsToExport    = @('*')
    GUID                 = 'b1325b42-8dc4-4f17-aa1f-dcb5984ca14a'
    ModuleVersion        = '2023.08'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            Tags                       = @('Windows', 'Locksmith', 'CA', 'PKI', 'Active Directory', 'Certificate Services', 'AD CS')
            ExternalModuleDependencies = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
        }
    }
    RequiredModules      = @('ActiveDirectory', 'ServerManager', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.LocalAccounts', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'CimCmdlets', 'Dism')
    RootModule           = 'Locksmith.psm1'
}