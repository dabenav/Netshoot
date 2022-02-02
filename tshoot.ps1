####################################################################################################################
#  Name: NetworkTroubleshooting.ps1
#  Task: To check network connectivity from local system to outside and Internal
#  Architech: Daniel Benavides
####################################################################################################################

Write-Host "`nStarting Network Connectivity test....." -ForegroundColor Gray

$result = $null
$data = $null
# Get IP Configuration details from Worksttion
$IPDetails = Get-NetIPConfiguration | where{ ($_.NetAdapter.Status -eq 'UP') -and ($_.IPv4DefaultGateway -ne $null) }
$result = @()

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
$speedtestdata = New-Object -TypeName psobject

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
    Write-Host "`nAverage Gateway response time is $average ms" -ForegroundColor Gray
    Write-Host "Success Rate: $((($pingCount - $lost) / $pingCount) * 100)%`n" -ForegroundColor Gray
}
elseIf($lost -lt $pingCount -and $lost -gt 0)
{
    $GetewayPingStatus = "Poor"    
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "`nAverage Gateway response time is $average ms" -ForegroundColor Gray
    Write-Host "Success Rate: $((($pingCount - $lost) / $pingCount) * 100)%`n" -ForegroundColor Gray
}
else
{
    $GetewayPingStatus = "Fail"
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "`nAverage Gateway response time is $average ms" -ForegroundColor Gray  
    Write-Host "Success Rate: $((($pingCount - $lost) / $pingCount) * 100)%`n" -ForegroundColor Gray  
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
        Write-Host "Average DNS response time is $average1 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost1) / $pingCount) * 100)%`n" -ForegroundColor Gray  
    }
    elseIf($lost1 -lt $pingCount -and $lost1 -gt 0)
    {
        $DNSPingBlnk = "Poor"       
        $data  | Add-Member -MemberType NoteProperty -Name "DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "Average DNS response time is $average1 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost1) / $pingCount) * 100)%`n" -ForegroundColor Gray
    }
    else
    {
        $DNSPingBlnk = "Fail"
        $data  | Add-Member -MemberType NoteProperty -Name "DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "Average DNS response time is $average1 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost1) / $pingCount) * 100)%`n" -ForegroundColor Gray
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
        Write-Host "Average Domain response time is $average2 ms" -ForegroundColor Gray
    }
    else
    {
        $data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Unreachable" -Force
        Write-Host "Average Domain response time is $average2 ms" -ForegroundColor Gray
    }             
}
else
{
    $data | Add-Member -MemberType NoteProperty -Name "Domain" -Value "No Domain Name" -Force
    Write-Host "The system is not joined to a domain`n" -ForegroundColor Gray
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
        Write-Host "$PDNS Average DNS response time is $average3 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost3) / $pingCount) * 100)%`n" -ForegroundColor Gray
    }
    elseIf($lost3 -lt $pingCount -and $lost3 -gt 0)
    {
        $PDNSPingBlnk = "Poor"       
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS Average DNS response time is $average3 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost3) / $pingCount) * 100)%`n" -ForegroundColor Gray
    }
    else
    {
        $PDNSPingBlnk = "Fail"
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS Average DNS response time is $average3 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost3) / $pingCount) * 100)%`n" -ForegroundColor Gray
    }
      
}

# DNS Resolution for public sites

foreach ($item in $PublicSites)
{
   $ItemIP = (Test-Connection $item -count 1 -ErrorAction SilentlyContinue).IPV4Address.IPAddressToString
   if ($ItemIP)
   {
      $data | Add-Member -MemberType NoteProperty -Name "DNS Resolve $item" -Value "Success" -Force
      Write-Host "DNS Resolved Successfully for $item" -ForegroundColor Gray
   }
   else
   {
      $data | Add-Member -MemberType NoteProperty -Name  $data  -Value "Failed" -Force
      Write-Host "DNS Resolved Successfully for $item" -ForegroundColor Gray
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
           Write-Host "Port Connectivity test completed for $tsite" -ForegroundColor Gray
       }
       else
       {
           $data | Add-Member -MemberType NoteProperty -Name "$tsite : $port" -Value "Failed" -Force
           Write-Host "Port Connectivity test completed for $tsite" -ForegroundColor Gray
       }
          
   }
}


####################### Get Public IP Address  ########################

$data | Add-Member -MemberType NoteProperty -Name "Public IP Address" -Value $PublicIPAddress



########################### getting output ############################

$result += $data

Write-Host "`n================ RESULTS ================" -ForegroundColor Green

$result


####################### Speed Test  ########################

Write-Host "`nRunning Speed Test..." -ForegroundColor Gray

$Speedtesturi = Invoke-WebRequest -Uri "https://www.speedtest.net/apps/cli" -UseBasicParsing
$downloaduri = $Speedtesturi.Links | Where-Object {$_.outerHTML -like "*Download for Windows*"}
Invoke-WebRequest -Uri $downloaduri.href -OutFile ".\speedtest.zip" 
Expand-Archive -Path ".\speedtest.zip" -DestinationPath ".\" -Force

$speedtestresult = &".\speedtest.exe" --accept-license --accept-gdpr --format=json | ConvertFrom-Json 

[PSCustomObject]$speedtestresult = @{
    downloadspeed = [math]::Round($Speedtest.download.bandwidth / 1000000 * 8, 2)
    uploadspeed   = [math]::Round($Speedtest.upload.bandwidth / 1000000 * 8, 2)
    packetloss    = [math]::Round($Speedtest.packetLoss)
    isp           = $Speedtest.isp
    Location      = $Speedtest.server.location
    ExternalIP    = $Speedtest.interface.externalIp
    InternalIP    = $Speedtest.interface.internalIp
    UsedServer    = $Speedtest.server.host
    URL           = $Speedtest.result.url
    Jitter        = [math]::Round($Speedtest.ping.jitter, 2)
    Latency       = [math]::Round($Speedtest.ping.latency, 2)
}

$speedtestdata | Add-Member -MemberType NoteProperty -Name "ISP" -Value $speedtestresult.isp -Force
$speedtestdata | Add-Member -MemberType NoteProperty -Name "Location" -Value $speedtestresult.location -Force
$speedtestdata | Add-Member -MemberType NoteProperty -Name "Download Speed" -Value $speedtestresult.downloadspeed -Force
$speedtestdata | Add-Member -MemberType NoteProperty -Name "Upload Speed" -Value $speedtestresult.uploadspeed -Force
$speedtestdata | Add-Member -MemberType NoteProperty -Name "Latency" -Value $speedtestresult.latency -Force
$speedtestdata | Add-Member -MemberType NoteProperty -Name "Jitter" -Value $speedtestresult.Jitter -Force
$speedtestdata | Add-Member -MemberType NoteProperty -Name "Packet Loss" -Value $speedtestresult.packetloss -Force
#$speedtestdata | Add-Member -MemberType NoteProperty -Name "External IP" -Value $speedtestresult.externalip -Force

Write-Host "`n================ SPEED TEST ================`n" -ForegroundColor Green

$speedtestdata

Write-Host "`n=== NETWORK CONNECTIVITY TEST COMPLETED ===" -ForegroundColor Green

##########################################################################################################################################
