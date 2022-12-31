# .ExternalHelp $PSScriptRoot\Connect-SCCM-help.xml
function Connect-SCCM {

    [CmdletBinding()]

    Param (

        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCredential]
        $Credential,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SiteCode,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProviderMachineName,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Domain,

        [Parameter()]
        [Switch]
        $SaveCredential,

        [Parameter()]
        [Switch]
        $PassThru,

        [Parameter()]
        [Switch]
        $Quiet
    )

    $windowVisible = if ($(Get-Process -Id $([System.Diagnostics.Process]::GetCurrentProcess().Id)).MainWindowHandle -eq 0) { $false } else { $true }

    if ($null -eq (Get-Module -Name ConfigurationManager)) {
        try {
            Import-Module "${env:SMS_ADMIN_UI_PATH}\..\ConfigurationManager.psd1" -Scope Global
        }
        catch {
            if ($windowVisible -and !($Quiet)) {
                Write-Host "SCCM Not Installed" -ForegroundColor Red
                pause
                return
            }
        }
    }

    if (!($Domain)) {
        if ($null -eq $script:Config.Domain) {
            $script:Config.Domain = Read-Host -Prompt 'Enter Domain'
        }
    }

    if (!($SiteCode)) {
        if ($null -eq $script:Config.SiteCode) {
            $script:Config.SiteCode = Read-Host -Prompt 'Enter Site Code'
        }
    }

    if (!($ProviderMachineName)) {
        if ($null -eq $script:Config.ProviderMachineName) {
            $script:Config.ProviderMachineName = Read-Host -Prompt 'Enter Provider Machine Name'
        }
    }

    $script:Config | Export-Clixml -Path "$PSScriptRoot\config.xml" -Depth 100

    if (!($Credential)) {
        if ($null -eq $script:Config.Credential) {
            $Credential = $Host.UI.PromptForCredential("SCCM Credentials", "Enter password for $($script:Config.Domain)\${env:USERNAME}", "$($script:Config.Domain)\${env:USERNAME}", '')
            $script:Config.Credential = $Credential
        }
    }
    else {
        $script:Config.Credential = $Credential
    }

    if ($SaveCredential) {
        $script:Config | Export-Clixml -Path "$PSScriptRoot\config.xml" -Depth 100
    }

    if ($null -eq (Get-PSDrive -Name $script:Config.SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
        try {
            $null = New-PSDrive -Name $script:Config.SiteCode -PSProvider CMSite -Root $script:Config.ProviderMachineName -Scope Global -Credential $script:Config.Credential
            if ($?) {
                if ($windowVisible -and !($Quiet)) {
                    Write-Host "Connected to SCCM Site - " -NoNewline
                    Write-Host $script:Config.SiteCode -ForegroundColor Green
                }
            }
            else {
                if ($windowVisible -and !($Quiet)) {
                    Write-Host "Failed to map SCCM Site - " -NoNewline
                    Write-Host $script:Config.SiteCode -ForegroundColor Red
                    pause
                    return
                }
            }
        }
        catch {
            if ($windowVisible -and !($Quiet)) {
                Write-Host "Failed to map SCCM Site - " -NoNewline
                Write-Host $script:Config.SiteCode -ForegroundColor Red
                pause
                return
            }
        }
    }
    else {
        if ($windowVisible -and !($Quiet)) {
            Write-Host "Connected to SCCM Site - " -NoNewline
            Write-Host $script:Config.SiteCOde -ForegroundColor Green
        }
    }

    if (Get-Location -StackName $MyInvocation.MyCommand.ModuleName -ErrorAction SilentlyContinue) {
        Pop-Location -StackName $MyInvocation.MyCommand.ModuleName
    }

    if ($PassThru) {
        $script:Config
    }
}
