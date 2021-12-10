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
$DNSs = (Get-DnsClientServerAddress).ServerAddresses|where{$_.length -lt '16'}
$domain = (Get-WmiObject win32_computersystem).Domain

############## Edit these variables as needed ###################

$PublicDNS = "8.8.8.8", "1.1.1.1"
$PublicSites = "ibm.com", "cisco.com"
$pingCount = 10

#################################################################

# Local Domain Joined Status

if ($domain -ne "Workgroup")
{  
  $domainPing = Test-Connection $domain -count $pingCount -ErrorAction SilentlyContinue
  $average2 = ($domainPing.ResponseTime | Measure-Object -Average).Average
  $data | Add-Member -MemberType NoteProperty -Name "Domain" -Value $domain -Force
    if ($domainPing)
    {
        $data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Reachable" -Force
        Write-Host "DOMAIN ping responsetime is $average2 ms" -ForegroundColor Gray
    }
    else
    {
        $data | Add-Member -MemberType NoteProperty -Name "Domain Status" -Value "Domain Unreachable" -Force
        Write-Host "DOMAIN ping responsetime is $average2 ms" -ForegroundColor Gray
    }             
}
else
{
    $data | Add-Member -MemberType NoteProperty -Name "Domain" -Value "No Domain Name" -Force
    Write-Host "System not added in domain`n" -ForegroundColor Gray
}

# Test Geteway Ping
$con = Test-Connection $Geteway -count $pingCount -ErrorAction SilentlyContinue
$average = ($con.ResponseTime | Measure-Object -Average).Average
$lost = $pingCount-($con.count)

$data = New-Object -TypeName psobject

if ($lost -eq 0 )
{
    $GetewayPingStatus = "Excelent"   
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "`nGateway ping status collected and response time is $average ms" -ForegroundColor Gray
    Write-Host "Success Rate: $((($pingCount - $lost) / $pingCount) * 100)%`n" -ForegroundColor Gray
}
elseIf($lost -lt $pingCount -and $lost -gt 0)
{
    $GetewayPingStatus = "Poor"    
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "`nGateway ping status collected and response time is $average ms" -ForegroundColor Gray
    Write-Host "Success Rate: $((($pingCount - $lost) / $pingCount) * 100)%`n" -ForegroundColor Gray
}
else
{
    $GetewayPingStatus = "Fail"
    $data | Add-Member -MemberType NoteProperty -Name GetewayPing -Value $GetewayPingStatus -Force
    Write-Host "`nGateway ping status collected and response time is $average ms" -ForegroundColor Gray  
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
        Write-Host "DNS ping status collected and response time is $average1 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost1) / $pingCount) * 100)%`n" -ForegroundColor Gray  
    }
    elseIf($lost1 -lt $pingCount -and $lost1 -gt 0)
    {
        $DNSPingBlnk = "Poor"       
        $data  | Add-Member -MemberType NoteProperty -Name "DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "DNS ping status collected and response time is $average1 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost1) / $pingCount) * 100)%`n" -ForegroundColor Gray
    }
    else
    {
        $DNSPingBlnk = "Fail"
        $data  | Add-Member -MemberType NoteProperty -Name "DNS $DNS" -Value $DNSPingBlnk -Force
        Write-Host "DNS ping status collected and response time is $average1 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost1) / $pingCount) * 100)%`n" -ForegroundColor Gray
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
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS DNS ping responsetime is $average3 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost3) / $pingCount) * 100)%`n" -ForegroundColor Gray
    }
    elseIf($lost3 -lt $pingCount -and $lost3 -gt 0)
    {
        $PDNSPingBlnk = "Poor"       
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS DNS ping responsetime is $average3 ms" -ForegroundColor Gray
        Write-Host "Success Rate: $((($pingCount - $lost3) / $pingCount) * 100)%`n" -ForegroundColor Gray
    }
    else
    {
        $PDNSPingBlnk = "Fail"
        $data | Add-Member -MemberType NoteProperty -Name $PDNS -Value $PDNSPingBlnk -Force
        Write-Host "$PDNS DNS ping responsetime is $average3 ms" -ForegroundColor Gray
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
 Write-Host "`nNetwork Connectivity test COMPLETED " -ForegroundColor Green

##########################################################################################################################################
