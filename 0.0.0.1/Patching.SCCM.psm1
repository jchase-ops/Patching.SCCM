# Patching.SCCM Module

#region Classes
################################################################################
#                                                                              #
#                                 CLASSES                                      #
#                                                                              #
################################################################################
# . "$PSScriptRoot\$(Split-Path -Path $(Split-Path -Path $PSScriptRoot -Parent) -Leaf).Classes.ps1"
#endregion

#region Variables
################################################################################
#                                                                              #
#                               VARIABLES                                      #
#                                                                              #
################################################################################
try {
    $script:Config = Import-Clixml -Path "$PSScriptRoot\config.xml" -ErrorAction Stop
}
catch {
    $script:Config = [ordered]@{
        SiteCode = $null
        ProviderMachineName = $null
        Domain = $null
        Credential = $null
        RunningScripts = $null
    }
    $script:Config | Export-Clixml -Path "$PSScriptRoot\config.xml" -Depth 100
}
#endregion

#region DotSourcedScripts
################################################################################
#                                                                              #
#                           DOT-SOURCED SCRIPTS                                #
#                                                                              #
################################################################################
. "$PSScriptRoot\Connect-SCCM.ps1"
. "$PSScriptRoot\Disconnect-SCCM.ps1"
. "$PSScriptRoot\Start-CMScriptInvocation.ps1"
. "$PSScriptRoot\Receive-CMScriptInvocation.ps1"
#endregion

#region ModuleMembers
################################################################################
#                                                                              #
#                              MODULE MEMBERS                                  #
#                                                                              #
################################################################################
Export-ModuleMember -Function Connect-SCCM
Export-ModuleMember -Function Disconnect-SCCM
Export-ModuleMember -Function Start-CMScriptInvocation
Export-ModuleMember -Function Receive-CMScriptInvocation
#endregion
