#
# Module manifest for module 'Broadcom.Community.VDefendSSP'
#
# Generated on: 09/20/26
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'Broadcom.Community.VDefendSSP.psm1'

# Version number of this module.
ModuleVersion = '1.0.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '2bd7781a-5090-4642-8991-9039272a807f'

# Author of this module
Author = 'William Lam'

# Company or vendor of this module
CompanyName = 'Broadcom'

# Copyright statement for this module
Copyright = '(c) 2026 Broadcom. All rights reserved.'

# Description of the functionality provided by this module
Description = 'PowerShell Module for automating vDefend Security Services Platform (SSP) 5.2 Configuration & Instance Deployments'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '7.0'

RequiredModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Approve-SspInstallerEula', 'Connect-SspInstaller', 'Connect-SspInstance', 'Get-SspInstallerDeployment', 'Get-SspInstallerEula', 'Get-SspInstallerPackage', 'Get-SspInstallerVCenterServer', 'Get-SspInstanceNsx', 'New-SspInstallerDeployment', 'New-SspInstallerPackage', 'New-SspInstallerVCenterServer', 'New-SspInstanceNsx', 'Remove-SspInstallerDeployment', 'Remove-SspInstallerPackage', 'Remove-SspInstallerVCenterServer', 'Remove-SspInstanceNsx'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('Broadcom','VCF','SSP')

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/lamw/Broadcom.Community.VDefendSSP'

        # A URL to an icon representing this module.
        IconUri = 'https://github.com/lamw/Broadcom.Community.VDefendSSP/raw/master/icon.png'

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}