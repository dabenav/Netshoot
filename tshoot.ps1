####################################################################################################################
#  Name: NetworkTroubleshooting Script
#  Task: To verify the network connectivity performance and errors
#  By: Daniel Benavides
####################################################################################################################

Write-Host "`nStarting Network Connectivity test....." -ForegroundColor DarkGray

$result = $null
$data = $null
$SpeedTestData = $null
$SpeedTestresults = $null
$result = @()
$SpeedTestresults = @()
# Clear WiFi variables
$CurrentTime = '' 
$Name = '' 
$Description = '' 
$GUID = '' 
$Physical = '' 
$State = '' 
$SSID = '' 
$BSSID = '' 
$NetworkType = '' 
$RadioType = '' 
$Authentication = '' 
$Cipher = '' 
$Connection = '' 
$Channel = '' 
$RecRate = '' 
$TransRate = '' 
$SignalLevelPercent = '' 
$SignalLeveldBm = 0
$Profile = ''

$wifidata = $null
$wifidata = New-Object -TypeName psobject
$wifiresult = $null
$wifiresult = @()
$data = New-Object -TypeName psobject
$SpeedTestData = New-Object -TypeName psobject


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

$IPDetails = $null
$IPDetails = Get-NetIPConfiguration | where{ ($_.InterfaceIndex -eq $DefaultIfIndex)}

$InterfacesUp = (Get-NetIPConfiguration | where{ $_.NetAdapter.Status -eq 'UP'}).InterfaceAlias
$IfUpDescriptions = (Get-NetIPConfiguration | where{ $_.NetAdapter.Status -eq 'UP'}).InterfaceDescription
$counter = 1
$IP = $IPDetails.IPv4Address.IPAddress
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

#$data | Add-Member -MemberType NoteProperty -Name "Interface Name" -Value $IPDetails.NetAdapter.Name


### Print Public IP Address 

Write-Host "The Public IP Address is: $PublicIPAddress" -ForegroundColor DarkGray


####################################### WiFi Settings ########################################


if ($IPDetails.InterfaceAlias -like '*Wi-Fi*')
{  
    Write-Host "`nWiFi Information...`n" -ForegroundColor DarkGray

    #Run netsh command to get wirelss profile info
    $NetshOut = netsh.exe wlan show interfaces

    # Get time to time-stamp entry
    $CurrentTime = Get-Date

    # Name
    $Name_line = $NetshOut | Select-String -Pattern 'Name'
    $Name = ($Name_line -split ":")[-1].Trim()

    # Description
    $Description_line = $NetshOut | Select-String -Pattern 'Description'
    $Description = ($Description_line -split ":")[-1].Trim()

    # GUID
    $GUID_line = $NetshOut | Select-String -Pattern 'GUID'
    $GUID = ($GUID_line -split ":")[-1].Trim()

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
    #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Network" -Value $SSID -Force


    ### BSSID
    $BSSID_line = $NetshOut | Select-String -Pattern 'BSSID'
    $BSSID = ($BSSID_line -split ":", 2)[-1].Trim()
    
    Write-Host ("The BSSID is: " + $BSSID ) -ForegroundColor DarkGray


    ### NetworkType
    $NetworkType_line = $NetshOut | Select-String -Pattern 'Network type'
    $NetworkType = ($NetworkType_line -split ":")[-1].Trim()

    ### RadioType
    $RadioType_line = $NetshOut | Select-String -Pattern 'Radio type'
    $RadioType = ($RadioType_line -split ":")[-1].Trim()

    Write-Host ("The protocol is: " + $RadioType ) -ForegroundColor DarkGray


    ### Authentication
    $Authentication_line = $NetshOut | Select-String -Pattern 'Authentication'
    $Authentication = ($Authentication_line -split ":")[-1].Trim()

    Write-Host ("The Authentication is: " + $Authentication ) -ForegroundColor DarkGray


    ### Cipher
    $Cipher_line = $NetshOut | Select-String -Pattern 'Cipher'
    $Cipher = ($Cipher_line -split ":")[-1].Trim()

    ### Connection mode
    $Connection_line = $NetshOut | Select-String -Pattern 'Connection mode'
    $Connection = ($Connection_line -split ":")[-1].Trim()

    ### Channel
    $Channel_line = $NetshOut | Select-String -Pattern 'Channel'
    $Channel = ($Channel_line -split ":")[-1].Trim()

    Write-Host ("The Channel is: " + $Channel ) -ForegroundColor DarkGray


    # Signal (%)
    $SignalLevelPercent_line = $NetshOut | Select-String -Pattern 'Signal'
    $SignalLevelPercent = ($SignalLevelPercent_line -split ":")[-1].Trim()
    $SignalPercentInt = [int]($SignalLevelPercent -replace ".$")

    if ($SignalPercentInt -lt 50){
        $wifisignal = "Bad"        
        #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Signal" -Value $wifisignal -Force
    }
    elseIf($SignalPercentInt -lt 80){
        $wifisignal = "Medium"       
        #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Signal" -Value $wifisignal -Force
    }
    else{
        $wifisignal = "Excellent"
        #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Signal" -Value $wifisignal -Force
    }

    # Signal (dBm)
    $SignalLevelPercent_trimmed = $SignalLevelPercent.TrimEnd('%')
    $SignalLeveldBm = (([int]$SignalLevelPercent_trimmed)/2) - 100

    Write-Host ("The Signal is: " +$SignalLevelPercent +" ," +$SignalLeveldBm +" dBm") -ForegroundColor DarkGray


    ### Receive Rate
    $RecRate_line = $NetshOut | Select-String -Pattern 'Receive rate'
    $RecRate = [int]($RecRate_line -split ":")[-1].Trim()

    Write-Host ("The Receive Rate is: " + $RecRate +" Mbps" ) -ForegroundColor DarkGray

    if ($RecRate -lt 5){
        $wifidownspeed = "Low"        
        #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Download Speed" -Value $wifidownspeed -Force
    }
    elseIf($RecRate -lt 10){
        $wifidownspeed = "Medium"       
        #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Download Speed" -Value $wifidownspeed -Force
    }
    else{
        $wifidownspeed = "Fast"
        #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Download Speed" -Value $wifidownspeed -Force
    }


    # Transmit Rate
    $TransRate_line = $NetshOut | Select-String -Pattern 'Transmit rate'
    $TransRate = [int]($TransRate_line -split ":")[-1].Trim()

    Write-Host ("The Transmit Rate is: " + $TransRate +" Mbps" ) -ForegroundColor DarkGray

    if ($TransRate -lt 5){
        $wifiuploadspeed = "Low"        
        #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Upload Speed" -Value $wifiuploadspeed -Force
    }
    elseIf($TransRate -lt 10){
        $wifiuploadspeed = "Medium"       
        #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Upload Speed" -Value $wifiuploadspeed -Force
    }
    else{
        $wifiuploadspeed = "Fast"
        #$wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Upload Speed" -Value $wifiuploadspeed -Force
    }


    # Profile
    $Profile_line = $NetshOut | Select-String -Pattern 'Profile'
    $Profile = ($Profile_line -split ":")[-1].Trim()
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
            Write-Host "Ping test hop #$hop $TraceHop response time Min/Avg/Max = $Minimum5/$average5/$Maximum5 ms, Packet Loss $lostpercentage5%" -ForegroundColor DarkGray
        }
        else
        {
            Write-Host "Ping test hop #$hop $TraceHop response time Min/Avg/Max = $Minimum5/$average5/$Maximum5 ms, Packet Loss $lostpercentage5%" -ForegroundColor DarkRed
        }
        
    }
}

# Default Gateway connectivity test

#$con = Test-Connection $Geteway -count $pingCount -ErrorAction SilentlyContinue
#$average = [MATH]::Round(($con.ResponseTime | Measure-Object -Average).Average,2)
#$Minimum = ($con.ResponseTime | Measure-Object -Minimum).Minimum
#$Maximum = ($con.ResponseTime | Measure-Object -Maximum).Maximum
#$lost = $pingCount-($con.count)
#$lostpercentage = ($lost * 100) / $pingCount
#
#if ($lost -eq 0 )
#{
#    $GetewayPingStatus = "Excelent"   
#   #$data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
#    Write-Host "Default Gateway $Geteway response time Min/Avg/Max = $Minimum/$average/$Maximum ms, Packet Loss $lostpercentage%" -ForegroundColor DarkGray
#}
#elseIf($lost -lt $pingCount -and $lost -gt 0)
#{
#    $GetewayPingStatus = "Poor"    
#   #$data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
#    Write-Host "Default Gateway $Geteway response time Min/Avg/Max: $Minimum / $average / $Maximum ms, Packet Loss $lostpercentage%" -ForegroundColor DarkGray
#}
#else
#{
#    $GetewayPingStatus = "Fail"
#   #$data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
#    Write-Host "Default Gateway $Geteway response FAILED" -ForegroundColor DarkRed
#}

# Test DNS Connectivity

foreach ($DNS in $DNSs)
{
    $DNSPingBlnk = @()
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
        Write-Host "Ping test to Host DNS server $DNS response time Min/Avg/Max = $Minimum1/$average1/$Maximum1 ms, Packet Loss $lostpercentage1%" -ForegroundColor DarkRed
    }

    

    #if ($lost1 -eq 0 )
    #{
    #    $DNSPingBlnk = "Excelent"        
    #    #$data  | Add-Member -MemberType NoteProperty -Name "System DNS $DNS" -Value $DNSPingBlnk -Force
    #    Write-Host "Ping DNS server $DNS response time Min/Avg/Max = $Minimum1/$average1/$Maximum1 ms, Packet Loss $lostpercentage1%" -ForegroundColor DarkGray 
    #}
    #elseIf($lost1 -lt $pingCount -and $lost1 -gt 0)
    #{
    #    $DNSPingBlnk = "Poor"       
    #    #$data  | Add-Member -MemberType NoteProperty -Name "System DNS $DNS" -Value $DNSPingBlnk -Force
    #    Write-Host "Ping DNS server $DNS response time Min/Avg/Max = $Minimum1/$average1/$Maximum1 ms, Packet Loss $lostpercentage1%" -ForegroundColor DarkGray 
    #}
    #else
    #{
    #    $DNSPingBlnk = "Fail"
    #    #$data  | Add-Member -MemberType NoteProperty -Name "System DNS $DNS" -Value $DNSPingBlnk -Force
    #    Write-Host "Ping DNS $DNS server FAILED" -ForegroundColor DarkRed 
    #}
}

# Public DNS Status

foreach ($PDNS in $PublicDNS)
{
    $PDNSPingBlnk = @()
    $con3 = Test-Connection $PDNS -count $pingCount -ErrorAction SilentlyContinue
    $average3 = [MATH]::Round(($con3.ResponseTime | Measure-Object -Average).Average,2)
    $Minimum3 = ($con3.ResponseTime | Measure-Object -Minimum).Minimum
    $Maximum3 = ($con3.ResponseTime | Measure-Object -Maximum).Maximum
    $lost3 = $pingCount-($con3.count)
    $lostpercentage3 = ($lost3 * 100) / $pingCount
    
    
    if ( $lost1 -eq 0 )
    {
        Write-Host "Ping test to Public DNS server $PDNS response time Min/Avg/Max = $Minimum3/$average3/$Maximum3 ms, Packet Loss $lostpercentage3%" -ForegroundColor DarkGray
    }
    else
    {
        Write-Host "Ping test to Public DNS server $PDNS response time Min/Avg/Max = $Minimum3/$average3/$Maximum3 ms, Packet Loss $lostpercentage3%" -ForegroundColor DarkRed
    }
    
    

    #if ($lost3 -eq 0 )
    #{
    #    #$PDNSPingBlnk = "Excelent"        
    #    #$data | Add-Member -MemberType NoteProperty -Name "Public DNS $PDNS" -Value $PDNSPingBlnk -Force
    #    Write-Host "Ping DNS server $PDNS response time Min/Avg/Max = $Minimum3/$average3/$Maximum3 ms, Packet Loss $lostpercentage3%" -ForegroundColor DarkGray
    #}
    #elseIf($lost3 -lt $pingCount -and $lost3 -gt 0)
    #{
    #    #$PDNSPingBlnk = "Poor"       
    #    #$data | Add-Member -MemberType NoteProperty -Name "Public DNS $PDNS" -Value $PDNSPingBlnk -Force
    #    Write-Host "Ping DNS server $PDNS response time Min/Avg/Max = $Minimum3/$average3/$Maximum3 ms, Packet Loss $lostpercentage3%" -ForegroundColor DarkGray
    #}
    #else
    #{
    #    #$PDNSPingBlnk = "Fail"
    #    #$data | Add-Member -MemberType NoteProperty -Name "Public DNS $PDNS" -Value $PDNSPingBlnk -Force
    #    Write-Host "Ping DNS server $PDNS Public DNS $PDNS response FAILED" -ForegroundColor DarkRed
    #}
      
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
 #$data | Add-Member -MemberType NoteProperty -Name "Domain Name" -Value $domain -Force
    
    if ($domainPing)
    {
        #$data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Reachable" -Force
        if ( $lost2 -eq 0 )
        {
            Write-Host "Domain Controller response time Min/Avg/Max = $Minimum2/$average2/$Maximum2 ms, Packet Loss $lostpercentage2%" -ForegroundColor DarkGray
        }
        else
        {
            Write-Host "Domain Controller response time Min/Avg/Max = $Minimum2/$average2/$Maximum2 ms, Packet Loss $lostpercentage2%" -ForegroundColor DarkRed
        }
        
    }
    else
    {
        #$data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Unreachable" -Force
        Write-Host "Domain Controller Unreachable -ForegroundColor DarkRed"
    }             
}
else
{
   #$data | Add-Member -MemberType NoteProperty -Name "Domain Name" -Value "No Domain Name" -Force
    Write-Host "The system is not joined to a domain" -ForegroundColor DarkRed
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
            #$data | Add-Member -MemberType NoteProperty -Name "DNS Resolved $item" -Value "Success" -Force
            Write-Host "DNS Resolver test for $DNS, $item $firstArecord - OK" -ForegroundColor DarkGray
        }
        else
        {
            #$data | Add-Member -MemberType NoteProperty -Name  "DNS $data"  -Value "Failed" -Force
            Write-Host "DNS Resolver test for $DNS FAILED" -ForegroundColor DarkRed
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
          #$data | Add-Member -MemberType NoteProperty -Name "$tsite : $port" -Value "Success" -Force
           Write-Host "Port Connectivity test for $tsite on port $port - OK" -ForegroundColor DarkGray
       }
       else
       {
          #$data | Add-Member -MemberType NoteProperty -Name "$tsite : $port" -Value "Failed" -Force
           Write-Host "Port Connectivity test for $tsite on port $port FAILED" -ForegroundColor DarkRed
       }
   }
}



####################################### Speed Test #######################################

Write-Host "`nRunning Speed Test...`n" -ForegroundColor DarkGray

#$Speedtesturi = Invoke-WebRequest -Uri "https://www.speedtest.net/apps/cli" -UseBasicParsing
#$downloaduri = $Speedtesturi.Links | Where-Object {$_.outerHTML -like "*Download for Windows*"}
#Invoke-WebRequest -Uri $downloaduri.href -OutFile ".\speedtest.zip" 
Invoke-WebRequest -Uri https://github.com/dabenav/Netshoot/raw/main/speedtest.exe -OutFile ".\speedtest.exe"
Invoke-WebRequest -Uri https://github.com/dabenav/Netshoot/raw/main/speedtest.md -OutFile ".\speedtest.md"
#Expand-Archive -Path ".\speedtest.zip" -DestinationPath ".\" -Force

$SpeedTestResult = &".\speedtest.exe" --accept-license --format=json | ConvertFrom-Json


[PSCustomObject]$SpeedTestObject = @{
    downloadspeed = [math]::Round($SpeedTestResult.download.bandwidth / 1000000 * 8, 2)
    uploadspeed   = [math]::Round($SpeedTestResult.upload.bandwidth / 1000000 * 8, 2)
    ISP           = $SpeedTestResult.isp
    Location      = $SpeedTestResult.server.location
    Country       = $SpeedTestResult.server.country
    ExternalIP    = $SpeedTestResult.interface.externalIp
    InternalIP    = $SpeedTestResult.interface.internalIp
    UsedServer    = $SpeedTestResult.server.host
    URL           = $SpeedTestResult.result.url
    Jitter        = [math]::Round($SpeedTestResult.ping.jitter, 2)
    Latency       = [math]::Round($SpeedTestResult.ping.latency, 2)
}

# Speed Test Logs

Write-Host ("The Internet Service Provider is: " + $speedtestobject.ISP ) -ForegroundColor DarkGray
Write-Host ("The Speed Test Server Location is: " + $speedtestobject.Location ) -ForegroundColor DarkGray
Write-Host ("The Speed Test Server Country is: " + $speedtestobject.Country ) -ForegroundColor DarkGray
Write-Host ("The Download Spped is: " + $speedtestobject.downloadspeed +" Mbps") -ForegroundColor DarkGray
Write-Host ("The Upload speed is: " + $speedtestobject.uploadspeed + " Mbps") -ForegroundColor DarkGray
Write-Host ("The Latency is: " + $SpeedTestObject.latency + " ms") -ForegroundColor DarkGray
Write-Host ("The Jitter is: " + $SpeedTestObject.Jitter + " ms") -ForegroundColor DarkGray


### Analisis of the Speed Test 

# Analisis For ISP Download Speed

#$SpeedTestData | Add-Member -MemberType NoteProperty -Name "ISP" -Value $speedtestobject.ISP -Force

#if ($SpeedTestObject.downloadspeed -le 5)
#{
#    #$SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Download Speed" -Value "Slow" -Force
#}
#   elseif ($SpeedTestObject.downloadspeed -le 10) 
#   {
#        #$SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Download Speed" -Value "Good" -Force
#   }
#
#   else 
#   {
#        #$SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Download Speed" -Value "Excellent" -Force
#   }

# Analisis For ISP Upload Speed

#if ($SpeedTestObject.uploadspeed -le 2){
#    #$SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Upload Speed" -Value "Slow" -Force
#}
#
#    elseif ($SpeedTestObject.uploadspeed -le 5) {
#        #$SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Upload Speed" -Value "Good" -Force
#    }
#
#    else {
#        #$SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Upload Speed" -Value "Excellent" -Force
#    }

####################################### Deleting Files ########################################

#Remove-Item -Path .\speedtest.zip
Remove-Item -Path .\speedtest.exe
Remove-Item -Path .\speedtest.md
Remove-Item -Path .\ts.ps1

####################################### Printing output Analisis ########################################

#$result += $data
#$wifiresult += $wifidata
#$SpeedTestresults += $SpeedTestData
#
#Write-Host "`nNETWORKING TESTS " -ForegroundColor Green
#$result | Format-List
#
#if ($IPDetails.InterfaceAlias -eq "Wi-Fi")
#{
#    Write-Host   " WIFI SETTINGS " -ForegroundColor Green
#    $wifiresult | Format-List
#}
#
#Write-Host " SPEED TEST " -ForegroundColor Green
#$SpeedTestresults  | Format-List


Write-Host   "`nNetwork Connectivity Tests Completed`n" -ForegroundColor DarkGray


########################################### END ###############################################
