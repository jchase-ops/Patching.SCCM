# .ExternalHelp $PSScriptRoot\Start-CMScriptInvocation-help.xml
function Start-CMScriptInvocation {

    [CmdletBinding(DefaultParameterSetName = 'Device')]

    Param (

        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Device', ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $ComputerName,

        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Collection', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $CollectionName,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ScriptName,

        [Parameter(Position = 2, ParameterSetName = 'Device')]
        [Parameter(Position = 2, ParameterSetName = 'Collection')]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]
        $ScriptParameters = @{ OutputType = 'Json' },

        [Parameter(ParameterSetName = 'Device')]
        [Parameter(ParameterSetName = 'Collection')]
        [Switch]
        $Quiet
    )

    $windowVisible = if ($(Get-Process -Id $([System.Diagnostics.Process]::GetCurrentProcess().Id)).MainWindowHandle -eq 0) { $false } else { $true }

    if ($null -eq (Get-PSDrive -Name $script:Config.SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
        if ($windowVisible -and !($Quiet)) {
            Connect-SCCM
        }
        else {
            Connect-SCCM -Quiet
        }
    }
    else {
        if ($PWD.Path -ne "$($script:Config.SiteCode):\") {
            Push-Location -Path "$($script:Config.SiteCode):\" -StackName $MyInvocation.MyCommand.ModuleName
        }
    }

    $script:Config.RunningScripts = [System.Collections.Generic.List[System.Object]]::New()
    $ScriptInfo = Get-CMScript -ScriptName $ScriptName -Fast | Select-Object -Property ScriptName, ScriptGuid

    $RunspaceConfig = @{
        SiteCode            = $script:Config.SiteCode
        ProviderMachineName = $script:Config.ProviderMachineName
        Domain              = $script:Config.Domain
        Credential          = $script:Config.Credential
    }

    Switch ($PSCmdlet.ParameterSetName) {
        'Device' {
            $Sync = Initialize-RunspacePool -MaxRunSpaces $([int][math]::Ceiling($ComputerName.Count / 200))
            $runspaceLimit = [int][math]::Floor($ComputerName.Count / $Sync.Count)
            $runspaceRemainder = $ComputerName.Count % $Sync.Count
            $runspaceCount = 0
            $runspaceStart = 0
            if ($windowVisible -and !($Quiet)) {
                Write-Host "Creating Runspace:" -NoNewline
            }
            do {
                if ($windowVisible -and !($Quiet)) {
                    Write-Host " $($runspaceCount + 1)" -ForegroundColor Green -NoNewline
                }
                if ($runspaceCount -eq 0) {
                    $runspaceModifier = $runspaceLimit + $runspaceRemainder - 1
                }
                else {
                    $runspaceModifier = $runspaceStart + $runspaceLimit - 1
                }
                $runspaceList = $ComputerName[$runspaceStart..$runspaceModifier]
                $runspaceStart = $runspaceStart + $runspaceLimit
                $scriptBlock = [System.Management.Automation.ScriptBlock] {
                    Param($ComputerName, $ScriptInfo, $ScriptParameters, $Config, $RunspaceID)
                    Import-Module "$($env:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" -Scope Global
                    $null = New-PSDrive -Name $Config.SiteCode -PSProvider CMSite -Root $Config.ProviderMachineName -Scope Global -Credential $Config.Credential
                    Set-Location "$($Config.SiteCode):\"
                    $collection = [System.Collections.Generic.List[System.Object]]::New()
                    ForEach ($name in $ComputerName) {
                        $cmDevice = Get-CMDevice -Name $name -Fast
                        $obj = [PSCustomObject]@{
                            Name                        = $name
                            ClientOperationID           = $null
                            CompletedClients            = $null
                            FailedClients               = $null
                            NotApplicableClients        = $null
                            OfflineClients              = $null
                            TotalClients                = $null
                            LastUpdateTime              = $null
                            OverallScriptExecutionState = $null
                            ScriptStartTime             = Get-Date
                            ScriptName                  = $ScriptInfo.ScriptName
                            ScriptGuid                  = $ScriptInfo.ScriptGuid
                            TaskID                      = $null
                            Members                     = [PSCustomObject]@{
                                ComputerName     = $name
                                ADSiteName       = $cmDevice.ADSiteName
                                BoundaryGroups   = $cmDevice.BoundaryGroups
                                DeviceOS         = $cmDevice.DeviceOS
                                DeviceOSBuild    = $cmDevice.DeviceOSBuild
                                Domain           = $cmDevice.Domain
                                IsActive         = $cmDevice.IsActive
                                IsVirtualMachine = $cmDevice.IsVirtualMachine
                                LastActiveTime   = $cmDevice.LastActiveTime
                                ResourceID       = $cmDevice.ResourceID.ToString()
                                SerialNumber     = $cmDevice.SerialNumber
                                SMBIOSGUID       = $cmDevice.SMBIOSGUID
                                SMSID            = $cmDevice.SMSID
                                ScriptResults    = [System.Collections.Generic.List[System.Object]]::New()
                            }
                            Details                     = [System.Collections.Generic.List[System.Object]]::New()
                        }
                        if ([version]$cmDevice.DeviceOSBuild -ge 6.2) {
                            if (Test-Connection -ComputerName $name -Count 3 -Quiet) {
                                $obj.ClientOperationID = (Invoke-CMScript -ScriptGuid $obj.ScriptGuid -Device $cmDevice -ScriptParameter $ScriptParameters -PassThru).OperationId
                            }
                            else {
                                $obj.ClientOperationID = 'OFFLINE'
                            }
                        }
                        else {
                            if ($cmDevice.DeviceOSBuild -like "*6.1*") {
                                $obj.ClientOperationID = '2008_R2'
                            }
                            else {
                                $obj.ClientOperationID = '2008'
                            }
                        }
                        $Sync.$RunspaceID.Completed++
                        $collection.Add($obj)
                    }
                    $collection | Sort-Object -Property ComputerName
                }
                $Sync."Runspace_${runspaceCount}".Total = $runspaceList.Count
                $runspaceParams = @{
                    ComputerName     = $runspaceList
                    ScriptInfo       = $ScriptInfo
                    ScriptParameters = $ScriptParameters
                    Config           = $RunspaceConfig
                    RunspaceID       = "Runspace_${runspaceCount}"
                }
                Start-RunspaceJob -ID $($runspaceCount + 1) -ScriptBlock $scriptBlock -ParameterHash $runspaceParams
                $runspaceCount++
            } while ($runspaceCount -lt $Sync.Count)
        }
        'Collection' {
            $Sync = Initialize-RunspacePool -MaxRunSpaces $([int][math]::Ceiling($CollectionName.Count / 200))
            $runspaceLimit = [int][math]::Floor($CollectionName.Count / $Sync.Count)
            $runspaceRemainder = $CollectionName.Count % $Sync.Count
            $runspaceCount = 0
            $runspaceStart = 0
            if ($windowVisible -and !($Quiet)) {
                Write-Host "Creating Runspace:" -NoNewline
            }
            do {
                if ($windowVisible -and !($Quiet)) {
                    Write-Host " $($runspaceCount + 1)" -ForegroundColor Green -NoNewline
                }
                if ($runspaceCount -eq 0) {
                    $runspaceModifier = $runspaceLimit + $runspaceRemainder - 1
                }
                else {
                    $runspaceModifier = $runspaceStart + $runspaceLimit - 1
                }
                $runspaceList = $CollectionName[$runspaceStart..$runspaceModifier]
                $runspaceStart = $runspaceStart + $runspaceLimit
                $scriptBlock = [System.Management.Automation.ScriptBlock] {
                    Param($CollectionName, $ScriptInfo, $ScriptParameters, $Config, $RunspaceID)
                    Import-Module "$($env:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" -Scope Global
                    $null = New-PSDrive -Name $Config.SiteCode -PSProvider CMSite -Root $Config.ProviderMachineName -Scope Global -Credential $Config.Credential
                    Set-Location "$($Config.SiteCode):\"
                    $collection = [System.Collections.Generic.List[System.Object]]::New()
                    ForEach ($name in $CollectionName) {
                        $obj = [PSCustomObject]@{
                            Name                        = $name
                            ClientOperationID           = $null
                            CompletedClients            = $null
                            FailedClients               = $null
                            NotApplicableClients        = $null
                            OfflineClients              = $null
                            TotalClients                = $null
                            LastUpdateTime              = $null
                            OverallScriptExecutionState = $null
                            ScriptStartTime             = Get-Date
                            ScriptName                  = $ScriptInfo.ScriptName
                            ScriptGuid                  = $ScriptInfo.ScriptGuid
                            TaskID                      = $null
                            Members                     = [System.Collections.Generic.List[System.Object]]::New()
                            Details                     = [System.Collections.Generic.List[System.Object]]::New()
                        }
                        Get-CMCollectionMember -CollectionName $name | Sort-Object -Property Name | ForEach-Object {
                            $mem = [PSCustomObject]@{
                                ComputerName     = $_.Name
                                ADSiteName       = $_.ADSiteName
                                BoundaryGroups   = $_.BoundaryGroups
                                DeviceOS         = $_.DeviceOS
                                DeviceOSBuild    = $_.DeviceOSBuild
                                Domain           = $_.Domain
                                IsActive         = $_.IsActive
                                IsVirtualMachine = $_.IsVirtualMachine
                                LastActiveTime   = $_.LastActiveTime
                                ResourceID       = $_.ResourceID.ToString()
                                SerialNumber     = $_.SerialNumber
                                SMBIOSGUID       = $_.SMBIOSGUID
                                SMSID            = $_.SMSID
                                ScriptResults    = [System.Collections.Generic.List[System.Object]]::New()
                            }
                            $obj.Members.Add($mem)
                        }
                        $obj.Members = $obj.Members | Sort-Object -Property ComputerName
                        $obj.ClientOperationID = (Invoke-CMScript -ScriptGuid $obj.ScriptGuid -CollectionName $obj.Name -ScriptParameter $ScriptParameters -PassThru).OperationId
                        if ($null -eq $obj.ClientOperationID) {
                            $task = Get-WmiObject -ComputerName $Config.ProviderMachineName -Namespace "root\sms\site_$($Config.SiteCode)" -ClassName SMS_ScriptsExecutionTask -Filter "collectionName='$($obj.Name)' and scriptGuid='$($obj.ScriptGuid)'" -Credential $Config.Credential `
                            | Sort-Object -Property ClientOperationId | Select-Object -Last 1
                            $obj.ClientOperationID = $task.ClientOperationId
                        }
                        $collection.Add($obj)
                        $Sync.$RunspaceID.Completed++
                    }
                    $collection | Sort-Object -Property Name
                }
                $Sync."Runspace_${runspaceCount}".Total = $runspaceList.Count
                $runspaceParams = @{
                    CollectionName   = $runspaceList
                    ScriptInfo       = $ScriptInfo
                    ScriptParameters = $ScriptParameters
                    Config           = $RunspaceConfig
                    RunspaceID       = "Runspace_${runspaceCount}"
                }
                Start-RunspaceJob -ID $($runspaceCount + 1) -ScriptBlock $scriptBlock -ParameterHash $runspaceParams
                $runspaceCount++
            } while ($runspaceCount -lt $Sync.Count)
        }
    }
    if ($windowVisible -and !($Quiet)) {
        $script:Config.RunningScripts = Receive-RunspaceJob -Activity "Invoking $($ScriptInfo.ScriptName)" | Sort-Object -Property ComputerName
    }
    else {
        $script:Config.RunningScripts = Receive-RunspaceJob -Quiet | Sort-Object -Property ComputerName
    }

    if (Get-Location -StackName $MyInvocation.MyCommand.ModuleName -ErrorAction SilentlyContinue) {
        Pop-Location -StackName $MyInvocation.MyCommand.ModuleName
    }
}
