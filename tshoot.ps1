####################################################################################################################
#  Nmae: NetworkTroubleshooting.ps1
#  Task : To check network connectivity from local system to outside and Internal
####################################################################################################################

Write-Host "`nStarting Network Connectivity test....." -ForegroundColor Gray

$result = $null
$data = $null
#Get IP Configuration details from Worksttion
$IPDetails = Get-NetIPConfiguration | where{$_.NetAdapter.Status -eq 'UP'}
$result = @()

# Setting up standard variable for output as required

$counter = 1
$IP = $IPDetails.IPv4Address.IPAddress
$Getway = $IPDetails.IPv4DefaultGateway.NextHop
$DNSs = (Get-DnsClientServerAddress).ServerAddresses|where{$_.length -eq '12'}
$PublicDNS = "8.8.8.8", "1.1.1.1" #,"4.4.4.4"
$PublicSites = "www.google.com", "www.twitter.com"
$domain = (Get-WmiObject win32_computersystem).Domain


# Test Getway Ping

$pingCount = 5
$con = Test-Connection $Getway -count $pingCount -ErrorAction SilentlyContinue
$average = ($con.ResponseTime | Measure-Object -Average).Average
$lost = $pingCount-($con.count)

$data = New-Object -TypeName psobject

if ($lost -eq 0 )
{
    $GetwayPingStatus = "Excelent"   
    $data | Add-Member -MemberType NoteProperty -Name GetwayPing -Value $GetwayPingStatus -Force
    Write-Host "`nGateway ping status collected and responsetime is $average ms" -ForegroundColor Gray
}
elseIf($lost -lt 5 -and $lost -gt 0)
{
    $GetwayPingStatus = "Poor"    
    $data | Add-Member -MemberType NoteProperty -Name GetwayPing -Value $GetwayPingStatus -Force
    Write-Host "Gateway ping status collected and responsetime is $average ms" -ForegroundColor Gray  
}
else
{
    $GetwayPingStatus = "Fail"
    $data | Add-Member -MemberType NoteProperty -Name GetwayPing -Value $GetwayPingStatus -Force
    Write-Host "Gateway ping status collected and responsetime is $average ms" -ForegroundColor Gray    
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
        Write-Host "DNS ping status collected and responsetime is $average1 ms" -ForegroundColor Gray
    }
    elseIf($lost1 -lt 5 -and $lost1 -gt 0)
    {
        $DNSPingBlnk = "Poor"       
        $data  | Add-Member -MemberType NoteProperty -Name "DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "DNS ping status collected and responsetime is $average1 ms" -ForegroundColor Gray
    }
    else
    {
        $DNSPingBlnk = "Fail"
        $data  | Add-Member -MemberType NoteProperty -Name "DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "DNS ping status collected and responsetime is $average1 ms" -ForegroundColor Gray
    }
      
}


# Local Domain Joined Status

if ($domain)
{  
  $domainPing = Test-Connection $domain -count $pingCount -ErrorAction SilentlyContinue
  $average2 = ($domainPing.ResponseTime | Measure-Object -Average).Average
  $data | Add-Member -MemberType NoteProperty -Name "Domain" -Value $domain -Force
    if ($domainPing)
    {
        $data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Reachable" -Force
        Write-Host "DOMAIN ping status collected and responsetime is $average2 ms" -ForegroundColor Gray
    }
    else
    {
        $data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Unreachable" -Force
        Write-Host "DOMAIN ping status collected and responsetime is $average2 ms" -ForegroundColor Gray
    }             
}
else
{
    $data | Add-Member -MemberType NoteProperty -Name "Domain" -Value "No Domain Name" -Force
    Write-Host "System not added in domain" -ForegroundColor Gray
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
        Write-Host "$PDNS DNS ping status collected and responsetime is $average3 ms" -ForegroundColor Gray
    }
    elseIf($lost3 -lt 5 -and $lost3 -gt 0)
    {
        $PDNSPingBlnk = "Poor"       
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS DNS ping status collected and responsetime is $average3 ms" -ForegroundColor Gray
    }
    else
    {
        $PDNSPingBlnk = "Fail"
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS DNS ping status collected and responsetime is $average3 ms" -ForegroundColor Gray
    }
      
}

# DNS REsolution for public sites

$PublicSites1 = "google.com", "twitter.com"

foreach ($item in $PublicSites1)
{
   $ItemIP = (Test-Connection $item -count 1 -ErrorAction SilentlyContinue).IPV4Address.IPAddressToString
   if ($ItemIP)
   {
      $data | Add-Member -MemberType NoteProperty -Name "DNS Resolve $item" -Value "Success" -Force
      Write-Host "DNS Resolve Information collected for $item" -ForegroundColor Gray
   }
   else
   {
      $data | Add-Member -MemberType NoteProperty -Name  $data  -Value "Failed" -Force
      Write-Host "DNS Resolve Information collected for $item" -ForegroundColor Gray
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

# getting output

 $result += $data

 Write-Host "`n============ RESULTS ============" -ForegroundColor Green

 $result
 Write-Host "Completed Network Connectivity test, above report will help you to understand network issues......" -ForegroundColor Green

##########################################################################################################################################
