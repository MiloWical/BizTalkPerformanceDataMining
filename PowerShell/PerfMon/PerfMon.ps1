
$Config = Get-Content ".\PerfMon.config" | ConvertFrom-Json

$Tabs = 0;

function GetTabString
{
    $retVal = "";

    for ($i = 0; $i -lt $Tabs; $i++)
    {
        $retVal += "`t";
    }

    return $retVal
}

function WriteOutput($data)
{
    Write-Host "$(GetTabString) ${data}";
}

ForEach($HostEntry in $Config.Hosts) 
{
    WriteOutput("Host: $($HostEntry)");

    $Tabs++;

    ForEach($View in $Config.Views)
    {
        $ViewName = $View.Name;
        WriteOutput("View: $ViewName");

        WriteOutput("Counters:");

        $Tabs++;

        ForEach($Counter in $View.Counters)
        {
            $CounterName = $Counter.Category + "\" + $Counter.Counter;

            WriteOutput($CounterName);

            $Tabs++
            
                If($Counter.Instances -eq $null)
                {
                    $Instances = @([System.String]::Empty);        
                }
                Else 
                {
                    $Instances = $Counter.Instances    
                }

                ForEach($Instance in $Instances)
                {
                    $PerfMonCounter = New-Object System.Diagnostics.PerformanceCounter -ArgumentList $Counter.Category, $Counter.Counter, $Instance, $HostEntry;
                    $PerfMonValue = $PerfMonCounter.NextSample().RawValue;


                    If([System.String]::IsNullOrEmpty($Instance))
                    {
                        WriteOutput("Value: ${PerfMonValue}");
                    }
                    Else
                    {
                        WriteOutput("${Instance}: ${PerfMonValue}");
                    }
                }

            $Tabs--;
        }

        $Tabs--;
    }

    $Tabs--;

    Write-Host "";
}





<# 
$Counter = New-Object System.Diagnostics.PerformanceCounter -ArgumentList "Process", "% Processor Time", "_Total", "USECVUT-BTK01";

Write-Host $Counter.NextSample().RawValue;
#>