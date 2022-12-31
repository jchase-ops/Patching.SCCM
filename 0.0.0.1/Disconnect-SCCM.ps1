# .ExternalHelp $PSScriptRoot\Disconnect-SCCM-help.xml
function Disconnect-SCCM {

    [CmdletBinding()]

    Param ()

    if (Get-Location -StackName $MyInvocation.MyCommand.ModuleName) {
        Pop-Location -StackName $MyInvocation.MyCommand.ModuleName
    }

    if ($null -ne $(Get-PSDrive -PSProvider CMSite -ErrorAction SilentlyContinue)) {
        Get-PSDrive -PSProvider CMSite | Remove-PSDrive
    }
}
