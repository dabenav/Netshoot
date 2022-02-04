####################################################################################################################
#  Name: NetworkTroubleshooting Script
#  Task: To verify how is the network connectivity 
#  Architech: Daniel Benavides
####################################################################################################################

Write-Host "`nStarting Network Connectivity test....." -ForegroundColor DarkGray

$result = $null
$data = $null
$SpeedTestData = $null
$SpeedTestresults = $null
$result = @()
$SpeedTestresults = @()

# Get IP Configuration details from Worksttion

$IPDetails = Get-NetIPConfiguration | where{ ($_.NetAdapter.Status -eq 'UP') -and ($_.IPv4DefaultGateway -ne $null) }

# Setting up standard variable for output as required. Do not edit these variables.

$counter = 1
$IP = $IPDetails.IPv4Address.IPAddress
$Geteway = $IPDetails.IPv4DefaultGateway.NextHop
$DNSServers = $IPDetails.DNSServer | Where-Object {$_.AddressFamily -eq '2'}
$DNSs = $DNSServers.ServerAddresses
$domain = (Get-WmiObject win32_computersystem).Domain
$PublicIPAddress =  $(Resolve-DnsName -Name myip.opendns.com -Server 208.67.222.220).IPAddress

############## Edit these variables as needed ###################

$PublicDNS = "8.8.8.8", "1.1.1.1"
$PublicSites = "cisco.com", "ibm.com"
$pingCount = 2

#################################################################

$data = New-Object -TypeName psobject
$SpeedTestData = New-Object -TypeName psobject

############## Get Interface Name Information ###################

$data | Add-Member -MemberType NoteProperty -Name "Interface Name" -Value $IPDetails.NetAdapter.Name

##################### Geteway Ping Test #########################

$con = Test-Connection $Geteway -count $pingCount -ErrorAction SilentlyContinue
$average = ($con.ResponseTime | Measure-Object -Average).Average
$lost = $pingCount-($con.count)


if ($lost -eq 0 )
{
    $GetewayPingStatus = "Excelent"   
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "`nAverage Gateway response time is $average ms" -ForegroundColor DarkGray
    Write-Host "Success Rate: $((($pingCount - $lost) / $pingCount) * 100)%`n" -ForegroundColor DarkGray
}
elseIf($lost -lt $pingCount -and $lost -gt 0)
{
    $GetewayPingStatus = "Poor"    
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "`nAverage Gateway response time is $average ms" -ForegroundColor DarkGray
    Write-Host "Success Rate: $((($pingCount - $lost) / $pingCount) * 100)%`n" -ForegroundColor DarkGray
}
else
{
    $GetewayPingStatus = "Fail"
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "`nAverage Gateway response time is $average ms" -ForegroundColor DarkGray  
    Write-Host "Success Rate: $((($pingCount - $lost) / $pingCount) * 100)%`n" -ForegroundColor DarkGray  
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
        $data  | Add-Member -MemberType NoteProperty -Name "DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "Average DNS response time is $average1 ms" -ForegroundColor DarkGray
        Write-Host "Success Rate: $((($pingCount - $lost1) / $pingCount) * 100)%`n" -ForegroundColor DarkGray  
    }
    elseIf($lost1 -lt $pingCount -and $lost1 -gt 0)
    {
        $DNSPingBlnk = "Poor"       
        $data  | Add-Member -MemberType NoteProperty -Name "DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "Average DNS response time is $average1 ms" -ForegroundColor DarkGray
        Write-Host "Success Rate: $((($pingCount - $lost1) / $pingCount) * 100)%`n" -ForegroundColor DarkGray
    }
    else
    {
        $DNSPingBlnk = "Fail"
        $data  | Add-Member -MemberType NoteProperty -Name "DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "Average DNS response time is $average1 ms" -ForegroundColor DarkGray
        Write-Host "Success Rate: $((($pingCount - $lost1) / $pingCount) * 100)%`n" -ForegroundColor DarkGray
    }
      
}

# Local Domain Joined Status

if ($domain -ne "Workgroup")
{  
  $domainPing = Test-Connection $domain -count $pingCount -ErrorAction SilentlyContinue
  $average2 = ($domainPing.ResponseTime | Measure-Object -Average).Average
  $data | Add-Member -MemberType NoteProperty -Name "Domain" -Value $domain -Force
    if ($domainPing)
    {
        $data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Reachable" -Force
        Write-Host "Average Domain response time is $average2 ms" -ForegroundColor DarkGray
    }
    else
    {
        $data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Unreachable" -Force
        Write-Host "Average Domain response time is $average2 ms" -ForegroundColor DarkGray
    }             
}
else
{
    $data | Add-Member -MemberType NoteProperty -Name "Domain" -Value "No Domain Name" -Force
    Write-Host "The system is not joined to a domain`n" -ForegroundColor DarkGray
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
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS Average DNS response time is $average3 ms" -ForegroundColor DarkGray
        Write-Host "Success Rate: $((($pingCount - $lost3) / $pingCount) * 100)%`n" -ForegroundColor DarkGray
    }
    elseIf($lost3 -lt $pingCount -and $lost3 -gt 0)
    {
        $PDNSPingBlnk = "Poor"       
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS Average DNS response time is $average3 ms" -ForegroundColor DarkGray
        Write-Host "Success Rate: $((($pingCount - $lost3) / $pingCount) * 100)%`n" -ForegroundColor DarkGray
    }
    else
    {
        $PDNSPingBlnk = "Fail"
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS Average DNS response time is $average3 ms" -ForegroundColor DarkGray
        Write-Host "Success Rate: $((($pingCount - $lost3) / $pingCount) * 100)%`n" -ForegroundColor DarkGray
    }
      
}

# DNS Resolution for public sites

foreach ($item in $PublicSites)
{
   $ItemIP = (Test-Connection $item -count 1 -ErrorAction SilentlyContinue).IPV4Address.IPAddressToString
   if ($ItemIP)
   {
      $data | Add-Member -MemberType NoteProperty -Name "DNS Resolve $item" -Value "Success" -Force
      Write-Host "DNS Resolved Successfully for $item" -ForegroundColor DarkGray
   }
   else
   {
      $data | Add-Member -MemberType NoteProperty -Name  $data  -Value "Failed" -Force
      Write-Host "DNS Resolved Successfully for $item" -ForegroundColor DarkGray
   }
      
 }
 
# Telnet Test to public Sites on port 80 and 443

foreach ($tsite in $PublicSites)
{
   $ports = "443"  #"80"
   
   foreach ($port in $ports)
   {
       $telnetTest = Test-NetConnection -ComputerName $tsite -Port $port -ErrorAction SilentlyContinue
       if ($telnetTest.TcpTestSucceeded -eq "True")
       {
           $data | Add-Member -MemberType NoteProperty -Name "$tsite : $port" -Value "Success" -Force
           Write-Host "Port Connectivity test completed for $tsite" -ForegroundColor DarkGray
       }
       else
       {
           $data | Add-Member -MemberType NoteProperty -Name "$tsite : $port" -Value "Failed" -Force
           Write-Host "Port Connectivity test completed for $tsite" -ForegroundColor DarkGray
       }
          
   }
}

# Print Public IP Address 

Write-Host "The Public IP Address is $PublicIPAddress" -ForegroundColor DarkGray

########################### getting output ############################

$result += $data

Write-Host "`n================ RESULTS ================" -ForegroundColor Green

$result

########################### Speed Test Results ###########################

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

Write-Host ("The Internet Service Provider is " + $speedtestobject.ISP ) -ForegroundColor DarkGray
Write-Host ("The Speed Test Server Location is " + $speedtestobject.Location ) -ForegroundColor DarkGray
Write-Host ("The Speed Test Server Country is " + $speedtestobject.Country ) -ForegroundColor DarkGray
Write-Host ("The Download Spped is " + $speedtestobject.downloadspeed +" Mbps") -ForegroundColor DarkGray
Write-Host ("The Upload speed is " + $speedtestobject.uploadspeed + " Mbps") -ForegroundColor DarkGray
Write-Host ("The Latency is " + $SpeedTestObject.latency + " ms") -ForegroundColor DarkGray
Write-Host ("The Jitter is " + $SpeedTestObject.Jitter + " ms") -ForegroundColor DarkGray


# Analisis of the Speed Test 

# Analisis For Download Speed

$SpeedTestData | Add-Member -MemberType NoteProperty -Name "ISP" -Value $speedtestobject.ISP -Force

if ($SpeedTestObject.downloadspeed -le 5){
    $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Download Speed" -Value "Slow" -Force
}

   elseif ($SpeedTestObject.downloadspeed -le 10) {
        $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Download Speed" -Value "Good" -Force
    }

    else {
        $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Download Speed" -Value "Excellent" -Force
    }

# Analisis For Upload Speed

if ($SpeedTestObject.uploadspeed -le 2){
    $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Upload Speed" -Value "Slow" -Force
}

    elseif ($SpeedTestObject.uploadspeed -le 5) {
        $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Upload Speed" -Value "Good" -Force
    }

    else {
        $SpeedTestData | Add-Member -MemberType NoteProperty -Name "Upload Speed" -Value "Excellent" -Force
    }


# Print the Analisis for the Speed Test

Write-Host "`n================ SPEED TEST ================`n" -ForegroundColor Green

$SpeedTestresults += $SpeedTestData

$SpeedTestresults

Write-Host "==== NETWORK CONNECTIVITY TEST COMPLETED ====" -ForegroundColor DarkGray

##########################################################################################################################################
