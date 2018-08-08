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
        [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.BizTalk.ExplorerOM")
        $BizTalkDBInstance = $BizTalkGroup.MgmtDbServerName
        $BizTalkDB = $BizTalkGroup.MgmtDbName
        $BizTalkOM = New-Object Microsoft.BizTalk.ExplorerOM.BtsCatalogExplorer
        $BizTalkOM.ConnectionString = "SERVER=$BizTalkDBInstance;DATABASE=$BizTalkDB;Integrated Security=SSPI"

        $BizTalkWmiAccess = New-Object PSObject
        $BizTalkWmiAccess | Add-Member -type NoteProperty -Name 'BizTalkGroup' -Value $BizTalkGroup
        $BizTalkWmiAccess | Add-Member -type NoteProperty -Name 'BizTalkMsgBoxDb' -Value $BizTalkMsgBoxDb
        $BizTalkWmiAccess | Add-Member -type NoteProperty -Name 'BizTalkServer' -Value $BizTalkServer
        $BizTalkWmiAccess | Add-Member -type NoteProperty -Name 'BizTalkREG' -Value $BizTalkREG
        $BizTalkWmiAccess | Add-Member -type NoteProperty -Name 'HostInstances' -Value $HostInstances
        $BizTalkWmiAccess | Add-Member -type NoteProperty -Name 'TrackingHost' -Value $TrackingHost
        $BizTalkWmiAccess | Add-Member -type NoteProperty -Name 'BizTalkDBInstance' -Value $BizTalkDBInstance
        $BizTalkWmiAccess | Add-Member -type NoteProperty -Name 'BizTalkDB' -Value $BizTalkDB
        $BizTalkWmiAccess | Add-Member -type NoteProperty -Name 'BizTalkOM' -Value $BizTalkOM

        Write-Host "${HostName}: BizTalk WMI providers loaded successfully." -fore Green

        return $BizTalkWmiProvider;
    }
    catch {
        Write-Host $_.Exception.Message;

        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name;
        Write-Host "${HostName}: BizTalk not detected on this machine, or user ($CurrentUser) not member of BizTalk Administrators group" -fore Red
        return $null;
    }
}

function ProcessConfiguration ($configurationType, $Wmi)
{
    switch ($configurationType) {
        "ServerDetails" { ServerDetails($Wmi)  }
        Default { Write-Host "Invalid configuration: $configurationType" -fore Red}
    } 
}

function ReadConfigurationData ($HostConfiguration) 
{
    $WmiInterface = LoadHostWmiProviders($HostConfiguration.Name);

    If($WmiInterface -eq $null)
    {
        return;
    }

    foreach($config in $HostConfiguration.Configurations)
    {
        ProcessConfiguration($config);
    }
}

foreach($BizTalkHost in $Config.Hosts)
{
    ReadConfigurationData($BizTalkHost);
}




