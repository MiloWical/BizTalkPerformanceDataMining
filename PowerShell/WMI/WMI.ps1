$Config = Get-Content ".\WMI.config" | ConvertFrom-Json

$Tabs = 0;

function LoadHostWmiProviders($HostName)
{
    try { # Get BizTalk Information
        $BizTalkGroup = Get-WmiObject MSBTS_GroupSetting -namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName
        $BizTalkMsgBoxDb = Get-WmiObject MSBTS_MsgBoxSetting -namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName
        $BizTalkServer = Get-WmiObject MSBTS_Server -namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName
        
        #$registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $HostName).OpenSubKey("SOFTWARE\Microsoft\BizTalk Server\3.0")
        #$BizTalkREG = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $HostName).OpenSubKey("SOFTWARE\Microsoft\BizTalk Server\3.0") | Get-ItemProperty -ErrorAction Stop
        #$BizTalkREG = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\BizTalk Server\3.0' -ErrorAction Stop
        
        $HostInstances = Get-WmiObject MSBTS_HostInstance -namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName
        $TrackingHost = Get-WmiObject MSBTS_Host -Namespace root\MicrosoftBizTalkServer -ErrorAction Stop -ComputerName $HostName | Where-Object {$_.HostTracking -eq "true" }
        
        Add-Type -Path ".\Microsoft.RuleEngine.dll"
        Add-Type -Path ".\Microsoft.Biztalk.RuleEngineExtensions.dll"
        Add-Type -Path ".\Microsoft.BizTalk.ExplorerOM.dll"
        [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.BizTalk.ExplorerOM")
        $BizTalkDBInstance = $BizTalkGroup.MgmtDbServerName
        $BizTalkDB = $BizTalkGroup.MgmtDbName

        #$BizTalkOM = New-Object Microsoft.BizTalk.ExplorerOM.BtsCatalogExplorer
        #$BizTalkOM.ConnectionString = "SERVER=$BizTalkDBInstance;DATABASE=$BizTalkDB;Integrated Security=SSPI"
        
        $Products = Get-WmiObject win32_product -ErrorAction Stop -ComputerName $HostName

        $BizTalkWmiProvider = New-Object PSObject
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkGroup' -Value $BizTalkGroup
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkMsgBoxDb' -Value $BizTalkMsgBoxDb
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkServer' -Value $BizTalkServer
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkREG' -Value $BizTalkREG
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'HostInstances' -Value $HostInstances
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'TrackingHost' -Value $TrackingHost
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkDBInstance' -Value $BizTalkDBInstance
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkDB' -Value $BizTalkDB
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'BizTalkOM' -Value $BizTalkOM
        $BizTalkWmiProvider | Add-Member -type NoteProperty -Name 'Products' -Value $Products

        return $BizTalkWmiProvider;
    }
    catch {
        Write-Host $_.Exception.Message;

        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name;
        Write-Host "${HostName}: BizTalk not detected on this machine, or user ($CurrentUser) not member of BizTalk Administrators group" -fore Red
        return $null;
    }
}

function ServerDetails ($Wmi)
{
    Write-Host "Server Details: " -fore Blue

    Write-Host "`nBizTalk Information" -fore Green
    #Write-Host $BiztalkREG.ProductName "("$BiztalkREG.ProductEdition"Edition )"
    #Write-Host "Product Version:" $BiztalkREG.ProductVersion
    #Write-Host "Installation Path:" $BiztalkREG.InstallPath
    #Write-Host "Installation Date:" $BiztalkREG.InstallDate
    Write-Host "Server name:" $Wmi.BizTalkServer.Name
    Write-Host "SSO Server:" $Wmi.BizTalkGroup.SSOServerName
    Write-Host "BizTalk Admin group:" $Wmi.BizTalkGroup.BizTalkAdministratorGroup
    Write-Host "BizTalk Operators group:" $Wmi.BizTalkGroup.BizTalkOperatorGroup
    Write-Host "BizTalk Group Name:" $Wmi.BizTalkGroup.Name
    Write-Host "Cache Refresh Interval:" $Wmi.BizTalkGroup.ConfigurationCacheRefreshInterval

    switch ($Wmi.BizTalkGroup.GlobalTrackingOption) {
        0 { Write-Host "Global Tracking: Off" }
        1 { Write-Host "Global Tracking: On" }
    }
    Write-Host "`nInstalled BizTalk Software" -Fore DarkGray
    $Wmi.Products | where-object { $_.Name -like "*BizTalk*" } | select-object Name -Unique | Sort-Object Name | Select-Object -expand Name
}

function ProcessConfiguration ($configurationType, $Wmi)
{
    switch ($configurationType) {
        "ServerDetails" { ServerDetails($Wmi)  }
        Default { Write-Host "Invalid configuration type: $configurationType" -fore Red}
    } 
}

function ReadConfigurationData ($HostConfiguration) 
{
    $HostName = $HostConfiguration.Name;

    $WmiInterface = LoadHostWmiProviders($HostName);

    If($null -eq $WmiInterface)
    {
        return;
    }

    Write-Host "${HostName}: BizTalk WMI providers loaded successfully." -fore Green

    foreach($config in $HostConfiguration.Configurations)
    {
        ProcessConfiguration($config);
    }
}

foreach($BizTalkHost in $Config.Hosts)
{
    ReadConfigurationData($BizTalkHost);
}




