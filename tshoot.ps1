####################################################################################################################
#  Name: Network Troubleshooting Script
#  Task: To verify the network connectivity performance and errors
#  By: Daniel Benavides
#  Date: 25 Ago 2026
####################################################################################################################

Write-Host "`nStarting Network Connectivity test....." -ForegroundColor DarkGray


########################## Edit these variables as needed ###############################

$PublicDNS = "8.8.8.8"
$PublicSites = "cisco.com"
$pingCount = 8


########################## Get Interface Name Information ###############################

Write-Host "`nCollecting Information.....`n" -ForegroundColor DarkGray

### Get Best Route IP Configuration details

$NextHop =  Test-NetConnection 8.8.8.8  -DiagnoseRouting
$DefaultIfIndex = $NextHop.OutgoingInterfaceIndex
$DefaultInterface = $NextHop.OutgoingInterfaceAlias

Write-Host "The default interface is $DefaultInterface" -ForegroundColor DarkGray


# Setting up standard variable for output as required. Do not edit these variables.

$IPDetails = Get-NetIPConfiguration | where{ ($_.InterfaceIndex -eq $DefaultIfIndex)}

$InterfacesUp = (Get-NetIPConfiguration | where{ $_.NetAdapter.Status -eq 'UP'}).InterfaceAlias
$Geteway = $IPDetails.IPv4DefaultGateway.NextHop
$DNSServers = $IPDetails.DNSServer | Where-Object {$_.AddressFamily -eq '2'}
$DNSs = $DNSServers.ServerAddresses
$domain = (Get-WmiObject win32_computersystem).Domain
$PublicIPAddress =  $(Resolve-DnsName -Name myip.opendns.com -Server 208.67.222.220).IPAddress


### Interfaces UP

foreach ($InterfaceUp in $InterfacesUp)
    {
    $IfUpDetails = Get-NetIPConfiguration -InterfaceAlias $InterfaceUp
    $IfUpPrefixOrigin = $IfUpDetails.IPv4Address.PrefixOrigin
    $IfUpIPAddress = $IfUpDetails.IPv4Address.IPAddress
    $IfUpPrefixLength = $IfUpDetails.IPv4Address.PrefixLength
    $IfUpNextHop = $IfUpDetails.IPv4DefaultGateway.NextHop

    Write-Host "Interface $InterfaceUp is UP, $IfUpPrefixOrigin, $IfUpIPAddress/$IfUpPrefixLength $IfUpNextHop" -ForegroundColor DarkGray
    }

### Print Public IP Address 

Write-Host "The Public IP Address is: $PublicIPAddress" -ForegroundColor DarkGray`n


### Print CPU usage ##
$cpuAverage = (Get-WmiObject -Class win32_processor -ErrorAction Stop | Measure-Object -Property LoadPercentage -Average | Select-Object Average).Average

Write-Host "The CPU Average is: $cpuAverage" -ForegroundColor DarkGray

### Print RAM usage ##
$CompObject =  Get-WmiObject -Class WIN32_OperatingSystem
$RAM = [math]::Round((($CompObject.TotalVisibleMemorySize - $CompObject.FreePhysicalMemory)/1024/1024),2)

Write-Host "The RAM usage is: $RAM GB" -ForegroundColor DarkGray


####################################### WiFi Settings ########################################


if ($IPDetails.InterfaceAlias -like '*Wi-Fi*' -or $IPDetails.InterfaceAlias -like '*Wireless*')
{  
    Write-Host "`nWiFi Information...`n" -ForegroundColor DarkGray

    #Run netsh command to get wirelss profile info
    $NetshOut = netsh.exe wlan show interfaces

    # Physical Address
    $Physical_line = $NetshOut | Select-String -Pattern 'Physical'
    $Physical = ($Physical_line -split ":", 2)[-1].Trim()

    Write-Host ("The adapter mac address is: " + $Physical ) -ForegroundColor DarkGray

    # State
    $State_line = $NetshOut | Select-String -Pattern 'State'
    $State = ($State_line -split ":")[-1].Trim()

    if ($State -eq 'connected') {

    ### SSID
    $SSID_line = $NetshOut | Select-String 'SSID'| select -First 1
    $SSID = ($SSID_line -split ":")[-1].Trim()

    Write-Host ("The SSID is: " + $SSID ) -ForegroundColor DarkGray
    ### BSSID
    $BSSID_line = $NetshOut | Select-String -Pattern 'BSSID'
    $BSSID = ($BSSID_line -split ":", 2)[-1].Trim()
    
    Write-Host ("The BSSID is: " + $BSSID ) -ForegroundColor DarkGray


    ### RadioType
    $RadioType_line = $NetshOut | Select-String -Pattern 'Radio type'
    $RadioType = ($RadioType_line -split ":")[-1].Trim()

    $WiFiVersion = @{
        '802.11be' = 'Wi-Fi 7'
        '802.11ax' = 'Wi-Fi 6'
        '802.11ac' = 'Wi-Fi 5'
        '802.11n'  = 'Wi-Fi 4'
    }

    $Generation = $WiFiVersion[$RadioType]

    if (-not $Generation) {
        $Generation = 'Unknown'
    }

    Write-Host "The protocol is: $RadioType ( $Generation )" -ForegroundColor DarkGray


    ### Authentication
    $Authentication_line = $NetshOut | Select-String -Pattern 'Authentication'
    $Authentication = ($Authentication_line -split ":")[-1].Trim()

    Write-Host ("The Authentication is: " + $Authentication ) -ForegroundColor DarkGray


    ### Channel
    $Channel_line = $NetshOut | Select-String -Pattern 'Channel'
    $Channel = ($Channel_line -split ":")[-1].Trim()

    Write-Host ("The Channel is: " + $Channel ) -ForegroundColor DarkGray


    # Signal (%)
    $SignalLevelPercent_line = $NetshOut | Select-String -Pattern 'Signal'
    $SignalLevelPercent = ($SignalLevelPercent_line -split ":")[-1].Trim()

    # Signal (dBm)
    $SignalLevelPercent_trimmed = $SignalLevelPercent.TrimEnd('%')
    $SignalLeveldBm = (([int]$SignalLevelPercent_trimmed)/2) - 100

    Write-Host ("The Signal is: " +$SignalLevelPercent +" " +$SignalLeveldBm +" dBm") -ForegroundColor DarkGray


    ### Receive Rate
    $RecRate_line = $NetshOut | Select-String -Pattern 'Receive rate'
    $RecRate = [int]($RecRate_line -split ":")[-1].Trim()

    Write-Host ("The Receive Rate is: " + $RecRate +" Mbps" ) -ForegroundColor DarkGray


    # Transmit Rate
    $TransRate_line = $NetshOut | Select-String -Pattern 'Transmit rate'
    $TransRate = [int]($TransRate_line -split ":")[-1].Trim()

    Write-Host ("The Transmit Rate is: " + $TransRate +" Mbps" ) -ForegroundColor DarkGray
    }
}



################################# Tests #####################################

Write-Host "`nStarting Tests...`n" -ForegroundColor DarkGray

# Traceroute ping test

$TraceRouteTest = Test-NetConnection 8.8.8.8 -TraceRoute -Hops 3 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$TraceRouteHops = $TraceRouteTest.TraceRoute
$hop = 0

if (![string]::IsNullOrWhiteSpace($Geteway))
{
    foreach ($TraceHop in $TraceRouteHops)
    {
        $PingtestHop = Test-Connection $TraceHop -count $pingCount -ErrorAction SilentlyContinue
        $average5 = [MATH]::Round(($PingtestHop.ResponseTime | Measure-Object -Average).Average,2)
        $Minimum5 = ($PingtestHop.ResponseTime | Measure-Object -Minimum).Minimum
        $Maximum5 = ($PingtestHop.ResponseTime | Measure-Object -Maximum).Maximum
        $lost5 = $pingCount-($PingtestHop.count)
        $lostpercentage5 = ($lost5 * 100) / $pingCount
        $hop++

        if ( $lost5 -eq 0 )
        {
            Write-Host "Ping test to hop #$hop $TraceHop response time Min/Avg/Max = $Minimum5/$average5/$Maximum5 ms, Packet Loss $lostpercentage5%" -ForegroundColor DarkGray
        }
        else
        {
            Write-Host "Ping test to hop #$hop $TraceHop response time Min/Avg/Max = $Minimum5/$average5/$Maximum5 ms, Packet Loss $lostpercentage5%" -ForegroundColor DarkCyan
        }
        
    }
}

# Test DNS Connectivity

foreach ($DNS in $DNSs)
{
    $con1 = Test-Connection $DNS -count $pingCount -ErrorAction SilentlyContinue
    $average1 = [MATH]::Round(($con1.ResponseTime | Measure-Object -Average).Average,2)
    $Minimum1 = ($con1.ResponseTime | Measure-Object -Minimum).Minimum
    $Maximum1 = ($con1.ResponseTime | Measure-Object -Maximum).Maximum
    $lost1 = $pingCount-($con1.count)
    $lostpercentage1 = ($lost1 * 100) / $pingCount
    
    if ( $lost1 -eq 0 )
    {
        Write-Host "Ping test to Host DNS server $DNS response time Min/Avg/Max = $Minimum1/$average1/$Maximum1 ms, Packet Loss $lostpercentage1%" -ForegroundColor DarkGray
    }
    else
    {
        Write-Host "Ping test to Host DNS server $DNS response time Min/Avg/Max = $Minimum1/$average1/$Maximum1 ms, Packet Loss $lostpercentage1%" -ForegroundColor DarkCyan
    }

}

# Public DNS Status

foreach ($PDNS in $PublicDNS)
{
    $con3 = Test-Connection $PDNS -count $pingCount -ErrorAction SilentlyContinue
    $average3 = [MATH]::Round(($con3.ResponseTime | Measure-Object -Average).Average,2)
    $Minimum3 = ($con3.ResponseTime | Measure-Object -Minimum).Minimum
    $Maximum3 = ($con3.ResponseTime | Measure-Object -Maximum).Maximum
    $lost3 = $pingCount-($con3.count)
    $lostpercentage3 = ($lost3 * 100) / $pingCount
    
    
    if ( $lost3 -eq 0 )
    {
        Write-Host "Ping test to Public DNS server $PDNS response time Min/Avg/Max = $Minimum3/$average3/$Maximum3 ms, Packet Loss $lostpercentage3%" -ForegroundColor DarkGray
    }
    else
    {
        Write-Host "Ping test to Public DNS server $PDNS response time Min/Avg/Max = $Minimum3/$average3/$Maximum3 ms, Packet Loss $lostpercentage3%" -ForegroundColor DarkCyan
    }
}


# Local Domain Joined Status

if ($domain -ne "Workgroup")
{  
  $domainPing = Test-Connection $domain -count $pingCount -ErrorAction SilentlyContinue
  $average2 = [MATH]::Round(($domainPing.ResponseTime | Measure-Object -Average).Average,2)
  $Minimum2 = ($domainPing.ResponseTime | Measure-Object -Minimum).Minimum
  $Maximum2 = ($domainPing.ResponseTime | Measure-Object -Maximum).Maximum
  $lost2 = $pingCount-($domainPing.count)
  $lostpercentage2 = ($lost2 * 100) / $pingCount
    if ($domainPing)
    {
        if ( $lost2 -eq 0 )
        {
            Write-Host "Ping test to Domain Controller response time Min/Avg/Max = $Minimum2/$average2/$Maximum2 ms, Packet Loss $lostpercentage2%" -ForegroundColor DarkGray
        }
        else
        {
            Write-Host "Ping test to Domain Controller response time Min/Avg/Max = $Minimum2/$average2/$Maximum2 ms, Packet Loss $lostpercentage2%" -ForegroundColor DarkCyan
        }
        
    }
    else
    {
        Write-Host "Domain Controller Unreachable" -ForegroundColor DarkCyan
    }             
}
else
{
    Write-Host "The system is not joined to a domain" -ForegroundColor DarkCyan
}



# DNS Resolution test

foreach ($DNS in $DNSs)
{
    foreach ($item in $PublicSites)
    {
        $ItemIP = Resolve-DnsName $item -Server $DNS -ErrorAction SilentlyContinue
        $firstArecord = $ItemIP.IPAddress[1]
   
        if (![string]::IsNullOrWhiteSpace($ItemIP))
        {
            Write-Host "DNS Resolver test for $DNS, $item $firstArecord - OK" -ForegroundColor DarkGray
        }
        else
        {
            Write-Host "DNS Resolver test for $DNS FAILED" -ForegroundColor DarkCyan
        }
    }
 }
 
 
# Port test to public Sites on port 80 and 443

foreach ($tsite in $PublicSites)
{
   $ports = "80", "443"
   
   foreach ($port in $ports)
   {
       $telnetTest = Test-NetConnection -ComputerName $tsite -Port $port -ErrorAction SilentlyContinue
       if ($telnetTest.TcpTestSucceeded -eq "True")
       {
           Write-Host "Port Connectivity test for $tsite on port $port - OK" -ForegroundColor DarkGray
       }
       else
       {
           Write-Host "Port Connectivity test for $tsite on port $port FAILED" -ForegroundColor DarkCyan
       }
   }
}



####################################### Speed Test #######################################

Write-Host "`nRunning Speed Test..." -ForegroundColor DarkGray

$ScriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$SpeedTestPath = Join-Path $ScriptDirectory "speedtest.exe"
$SpeedTestUri = "https://raw.githubusercontent.com/dabenav/Netshoot/main/speedtest.exe"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Invoke-WebRequest -Uri $SpeedTestUri `
        -OutFile $SpeedTestPath `
        -UseBasicParsing `
        -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $SpeedTestPath -PathType Leaf)) {
        throw "The Speedtest executable was not downloaded."
    }

    for ($TestNumber = 1; $TestNumber -le 2; $TestNumber++) {
        if ($TestNumber -eq 2) {
            Start-Sleep -Seconds 3
        }

        Write-Host ""
        Write-Host "Speed Test #$TestNumber" -ForegroundColor DarkGray

        $SpeedTestJson = & $SpeedTestPath --accept-license --format=json

        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($SpeedTestJson)) {
            throw "Speed Test #$TestNumber did not return a valid result."
        }

        $SpeedTestResult = $SpeedTestJson | ConvertFrom-Json -ErrorAction Stop

        $SpeedTestObject = [PSCustomObject]@{
            downloadspeed = [math]::Round($SpeedTestResult.download.bandwidth / 1000000 * 8, 2)
            uploadspeed   = [math]::Round($SpeedTestResult.upload.bandwidth / 1000000 * 8, 2)
            ISP           = $SpeedTestResult.isp
            Location      = $SpeedTestResult.server.location
            Country       = $SpeedTestResult.server.country
            Jitter        = [math]::Round($SpeedTestResult.ping.jitter, 2)
            Latency       = [math]::Round($SpeedTestResult.ping.latency, 2)
        }

        Write-Host ("The Internet Service Provider is: " + $SpeedTestObject.ISP) -ForegroundColor DarkGray
        Write-Host ("The Speed Test Server Location is: " + $SpeedTestObject.Location) -ForegroundColor DarkGray
        Write-Host ("The Speed Test Server Country is: " + $SpeedTestObject.Country) -ForegroundColor DarkGray
        Write-Host ("The Download Speed is: " + $SpeedTestObject.downloadspeed + " Mbps") -ForegroundColor DarkGray
        Write-Host ("The Upload speed is: " + $SpeedTestObject.uploadspeed + " Mbps") -ForegroundColor DarkGray
        Write-Host ("The Latency is: " + $SpeedTestObject.latency + " ms") -ForegroundColor DarkGray
        Write-Host ("The Jitter is: " + $SpeedTestObject.Jitter + " ms") -ForegroundColor DarkGray
    }
}
catch {
    Write-Host "Speedtest could not be completed: $($_.Exception.Message)" -ForegroundColor DarkCyan
}
finally {
    if (Test-Path -LiteralPath $SpeedTestPath) {
        Remove-Item -LiteralPath $SpeedTestPath -Force -ErrorAction SilentlyContinue
    }
}


####################################### Deleting Files ########################################

Remove-Item -Path .\ts.ps1


Write-Host   "`nNetwork Connectivity Tests Completed`n" -ForegroundColor DarkGray


########################################### END ###############################################
