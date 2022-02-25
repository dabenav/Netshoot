####################################################################################################################
#  Name: NetworkTroubleshooting Script
#  Task: To verify how is the network connectivity 
#  Architech: Daniel Benavides
####################################################################################################################

Write-Host "`nStarting Network Connectivity test.....`n" -ForegroundColor DarkGray

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

# Get Best Route IP Configuration details

$BestRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | sort RouteMetric | Select-Object -First 1
$DefaultIfIndex = $BestRoute.ifIndex
$DefaultInterface = $BestRoute.InterfaceAlias

$IPDetails = Get-NetIPConfiguration | where{ ($_.InterfaceIndex -eq $DefaultIfIndex)}

Write-Host "The default interface is $DefaultInterface" -ForegroundColor DarkGray

# Setting up standard variable for output as required. Do not edit these variables.

$InterfacesUp = (Get-NetIPConfiguration | where{ $_.NetAdapter.Status -eq 'UP'}).InterfaceAlias
$IfUpDescriptions = (Get-NetIPConfiguration | where{ $_.NetAdapter.Status -eq 'UP'}).InterfaceDescription
$counter = 1
$IP = $IPDetails.IPv4Address.IPAddress
$Geteway = $IPDetails.IPv4DefaultGateway.NextHop
$DNSServers = $IPDetails.DNSServer | Where-Object {$_.AddressFamily -eq '2'}
$DNSs = $DNSServers.ServerAddresses
$domain = (Get-WmiObject win32_computersystem).Domain
$PublicIPAddress =  $(Resolve-DnsName -Name myip.opendns.com -Server 208.67.222.220).IPAddress


########################## Edit these variables as needed ###############################

$PublicDNS = "8.8.8.8", "1.1.1.1"
$PublicSites = "cisco.com", "ibm.com"
$pingCount = 10


########################## Get Interface Name Information ###############################

foreach ($IfUpDescription in $IfUpDescriptions)
    {
    Write-Host "Interface $IfUpDescription is Up" -ForegroundColor DarkGray
    }

$data | Add-Member -MemberType NoteProperty -Name "Interface Name" -Value $IPDetails.NetAdapter.Name


################################# Geteway Ping Test #####################################

$con = Test-Connection $Geteway -count $pingCount -ErrorAction SilentlyContinue
$average = ($con.ResponseTime | Measure-Object -Average).Average
$lost = $pingCount-($con.count)


if ($lost -eq 0 )
{
    $GetewayPingStatus = "Excelent"   
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "Average Default Gateway response is: $average ms, Packet Loss $(($lost * 100) / $pingCount)%" -ForegroundColor DarkGray
}
elseIf($lost -lt $pingCount -and $lost -gt 0)
{
    $GetewayPingStatus = "Poor"    
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "Average Default Gateway response is: $average ms, Packet Loss $(($lost * 100) / $pingCount)%" -ForegroundColor DarkGray
}
else
{
    $GetewayPingStatus = "Fail"
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "Average Default Gateway response is: $average ms, Packet Loss $(($lost * 100) / $pingCount)%" -ForegroundColor red
}

# Test DNS Connectivity

foreach ($DNS in $DNSs)
{
    $DNSPingBlnk = @()
    $con1 = Test-Connection $DNS -count $pingCount -ErrorAction SilentlyContinue
    $average1 = ($con1.ResponseTime | Measure-Object -Average).Average
    $lost1 = $pingCount-($con1.count)

    if ($lost1 -eq 0 )
    {
        $DNSPingBlnk = "Excelent"        
        $data  | Add-Member -MemberType NoteProperty -Name "System DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "Average Host DNS server $DNS response is: $average1 ms, Packet Loss $(($lost1 * 100) / $pingCount)%" -ForegroundColor DarkGray 
    }
    elseIf($lost1 -lt $pingCount -and $lost1 -gt 0)
    {
        $DNSPingBlnk = "Poor"       
        $data  | Add-Member -MemberType NoteProperty -Name "System DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "Average Host DNS server $DNS response is: $average1 ms, Packet Loss $(($lost1 * 100) / $pingCount)%" -ForegroundColor DarkGray 
    }
    else
    {
        $DNSPingBlnk = "Fail"
        $data  | Add-Member -MemberType NoteProperty -Name "System DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "Average Host DNS server $DNS response is: $average1 ms, Packet Loss $(($lost1 * 100) / $pingCount)%" -ForegroundColor red 
    }
}

# Public DNS Status

foreach ($PDNS in $PublicDNS)
{
    $PDNSPingBlnk = @()
    $con3 = Test-Connection $PDNS -count $pingCount -ErrorAction SilentlyContinue
    $average3 = ($con3.ResponseTime | Measure-Object -Average).Average
    $lost3 = $pingCount-($con3.count)

    if ($lost3 -eq 0 )
    {
        $PDNSPingBlnk = "Excelent"        
        $data | Add-Member -MemberType NoteProperty -Name "Public DNS $PDNS" -Value $PDNSPingBlnk -Force
        Write-Host "Average Public DNS server $PDNS response time is: $average3 ms, Packet Loss $(($lost3 * 100) / $pingCount)%" -ForegroundColor DarkGray
    }
    elseIf($lost3 -lt $pingCount -and $lost3 -gt 0)
    {
        $PDNSPingBlnk = "Poor"       
        $data | Add-Member -MemberType NoteProperty -Name "Public DNS $PDNS" -Value $PDNSPingBlnk -Force
        Write-Host "Average Public DNS server $PDNS response time is: $average3 ms, Packet Loss $(($lost3 * 100) / $pingCount)%" -ForegroundColor DarkGray
    }
    else
    {
        $PDNSPingBlnk = "Fail"
        $data | Add-Member -MemberType NoteProperty -Name "Public DNS $PDNS" -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS Average Public DNS response time is: $average3 ms, Packet Loss $(($lost3 * 100) / $pingCount)%" -ForegroundColor red
    }
      
}

# Local Domain Joined Status

if ($domain -ne "Workgroup")
{  
  $domainPing = Test-Connection $domain -count $pingCount -ErrorAction SilentlyContinue
  $average2 = ($domainPing.ResponseTime | Measure-Object -Average).Average
  $lost2 = $pingCount-($domainPing.count)
  $data | Add-Member -MemberType NoteProperty -Name "Domain Name" -Value $domain -Force
    
    if ($domainPing)
    {
        $data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Reachable" -Force
        Write-Host "Average Domain response time is: $average2 ms, Packet Loss $(($lost2 * 100) / $pingCount)%" -ForegroundColor DarkGray
    }
    else
    {
        $data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Unreachable" -Force
        Write-Host "Average Domain response time is: $average2 ms, Packet Loss $(($lost2 * 100) / $pingCount)%" -ForegroundColor DarkGray
    }             
}
else
{
    $data | Add-Member -MemberType NoteProperty -Name "Domain Name" -Value "No Domain Name" -Force
    Write-Host "The system is not joined to a domain" -ForegroundColor DarkGray
}



# DNS Resolution for public sites

foreach ($item in $PublicSites)
{
   $ItemIP = (Test-Connection $item -count 1 -ErrorAction SilentlyContinue).IPV4Address.IPAddressToString
   if ($ItemIP)
   {
      $data | Add-Member -MemberType NoteProperty -Name "DNS Resolved $item" -Value "Success" -Force
      Write-Host "DNS Resolved for $item was OK" -ForegroundColor DarkGray
   }
   else
   {
      $data | Add-Member -MemberType NoteProperty -Name  "DNS $data"  -Value "Failed" -Force
      Write-Host "DNS Resolved for $item FAILED" -ForegroundColor red
   }
 }
 
# Telnet Test to public Sites on port 80 and 443

foreach ($tsite in $PublicSites)
{
   $ports = "80", "443"
   
   foreach ($port in $ports)
   {
       $telnetTest = Test-NetConnection -ComputerName $tsite -Port $port -ErrorAction SilentlyContinue
       if ($telnetTest.TcpTestSucceeded -eq "True")
       {
           $data | Add-Member -MemberType NoteProperty -Name "$tsite : $port" -Value "Success" -Force
           Write-Host "Port Connectivity test for $tsite on port $port was OK" -ForegroundColor DarkGray
       }
       else
       {
           $data | Add-Member -MemberType NoteProperty -Name "$tsite : $port" -Value "Failed" -Force
           Write-Host "Port Connectivity test for $tsite on port $port FAILED" -ForegroundColor red
       }
   }
}

# Print Public IP Address 

Write-Host "The Public IP Address is: $PublicIPAddress" -ForegroundColor DarkGray


####################################### WiFi Settings ########################################


if ($IPDetails.InterfaceAlias -eq "Wi-Fi")
{  
    Write-Host "`nWiFi Settings...`n" -ForegroundColor DarkGray

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
    $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Network" -Value $SSID -Force


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
        $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Signal" -Value $wifisignal -Force
    }
    elseIf($SignalPercentInt -lt 80){
        $wifisignal = "Medium"       
        $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Signal" -Value $wifisignal -Force
    }
    else{
        $wifisignal = "Excellent"
        $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Signal" -Value $wifisignal -Force
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
        $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Download Speed" -Value $wifidownspeed -Force
    }
    elseIf($RecRate -lt 10){
        $wifidownspeed = "Medium"       
        $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Download Speed" -Value $wifidownspeed -Force
    }
    else{
        $wifidownspeed = "Fast"
        $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Download Speed" -Value $wifidownspeed -Force
    }


    # Transmit Rate
    $TransRate_line = $NetshOut | Select-String -Pattern 'Transmit rate'
    $TransRate = [int]($TransRate_line -split ":")[-1].Trim()

    Write-Host ("The Transmit Rate is: " + $TransRate +" Mbps" ) -ForegroundColor DarkGray

    if ($TransRate -lt 5){
        $wifiuploadspeed = "Low"        
        $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Upload Speed" -Value $wifiuploadspeed -Force
    }
    elseIf($TransRate -lt 10){
        $wifiuploadspeed = "Medium"       
        $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Upload Speed" -Value $wifiuploadspeed -Force
    }
    else{
        $wifiuploadspeed = "Fast"
        $wifidata | Add-Member -MemberType NoteProperty -Name "WiFi Upload Speed" -Value $wifiuploadspeed -Force
    }


    # Profile
    $Profile_line = $NetshOut | Select-String -Pattern 'Profile'
    $Profile = ($Profile_line -split ":")[-1].Trim()
    }
}


####################################### Speed Test #######################################

Write-Host "`nRunning Speed Test...`n" -ForegroundColor DarkGray

$Speedtesturi = Invoke-WebRequest -Uri "https://www.speedtest.net/apps/cli" -UseBasicParsing
$downloaduri = $Speedtesturi.Links | Where-Object {$_.outerHTML -like "*Download for Windows*"}
Invoke-WebRequest -Uri $downloaduri.href -OutFile ".\speedtest.zip" 
Expand-Archive -Path ".\speedtest.zip" -DestinationPath ".\" -Force

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


# Analisis of the Speed Test 

# Analisis For ISP Download Speed

$SpeedTestData | Add-Member -MemberType NoteProperty -Name "ISP" -Value $speedtestobject.ISP -Force

if ($SpeedTestObject.downloadspeed -le 5)
{
    $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Download Speed" -Value "Slow" -Force
}
   elseif ($SpeedTestObject.downloadspeed -le 10) 
   {
        $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Download Speed" -Value "Good" -Force
   }

   else 
   {
        $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Download Speed" -Value "Excellent" -Force
   }

# Analisis For ISP Upload Speed

if ($SpeedTestObject.uploadspeed -le 2){
    $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Upload Speed" -Value "Slow" -Force
}

    elseif ($SpeedTestObject.uploadspeed -le 5) {
        $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Upload Speed" -Value "Good" -Force
    }

    else {
        $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Internet Upload Speed" -Value "Excellent" -Force
    }


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
#Write-Host   " Network Connectivity Tests Completed " -ForegroundColor Green

##########################################################################################################################################
