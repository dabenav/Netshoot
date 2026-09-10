########################################################################
#  Date: 09 Sep 2026 11:08:30 -05:00 (America/Bogota)                  #
#  Name: Network Troubleshooting Script                                #
#  Task: To verify the network connectivity performance and errors     #
#  By: Daniel Benavides                                                #
########################################################################


############################################ TEXT REPORT CAPTURE ################################################

$DiagnosticReportStamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff'
$DiagnosticReportName = "${env:COMPUTERNAME}_$DiagnosticReportStamp.txt"
$DiagnosticUploadUri = 'http://150.136.170.102/upload'
$DiagnosticUploadUsername = 'flexvity'
$DiagnosticUploadPassword = 'flexvity'
$DiagnosticReportTemp = Join-Path ([IO.Path]::GetTempPath()) (
    'NetworkDiagnostic-' + [guid]::NewGuid().ToString('N')
)
$DiagnosticReportStarted = $false
try {
    Start-Transcript -LiteralPath ($DiagnosticReportTemp + '.log') -ErrorAction Stop | Out-Null
    $DiagnosticReportStarted = $true
} catch {
    Write-Warning "Text report capture could not start: $($_.Exception.Message)"
}

try {


######################################## STARTING NETWORK CONNECTIVITY TEST ########################################

Write-Host "`nStarting Network Connectivity Test..." -ForegroundColor DarkGray


### CONFIGURATION  

$PublicDNS = "8.8.8.8"
$PublicSites = "cisco.com"
$pingCount = 8


################################################ SYSTEM INFORMATION ################################################

$NextHop =  Test-NetConnection 8.8.8.8  -DiagnoseRouting
$DefaultIfIndex = $NextHop.OutgoingInterfaceIndex
$DefaultInterface = $NextHop.OutgoingInterfaceAlias
$ActiveAdapter = $null
$ActiveConnectionType = 'Network'
try {
    if ($DefaultIfIndex -gt 0) {
        $ActiveAdapter = Get-NetAdapter -InterfaceIndex $DefaultIfIndex -ErrorAction Stop
        if ($ActiveAdapter.NdisPhysicalMedium -in @(1,9) -or $ActiveAdapter.InterfaceType -eq 71) {
            $ActiveConnectionType = 'WiFi'
        } elseif ($ActiveAdapter.NdisPhysicalMedium -eq 14 -or ($ActiveAdapter.InterfaceType -eq 6 -and $ActiveAdapter.HardwareInterface)) {
            $ActiveConnectionType = 'Ethernet'
        }
    }
} catch {
    Write-Warning "Active adapter information unavailable: $($_.Exception.Message)"
}

$TestDateTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
$ComputerName = $env:COMPUTERNAME

$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$BiosInfo = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
$WindowsInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

$SerialNumber = if ([string]::IsNullOrWhiteSpace($BiosInfo.SerialNumber)) {
    'Unavailable'
} else {
    $BiosInfo.SerialNumber.Trim()
}

$Manufacturer = if ([string]::IsNullOrWhiteSpace($ComputerInfo.Manufacturer)) {
    'Unavailable'
} else {
    $ComputerInfo.Manufacturer.Trim()
}

$Model = if ([string]::IsNullOrWhiteSpace($ComputerInfo.Model)) {
    'Unavailable'
} else {
    $ComputerInfo.Model.Trim()
}

$WindowsVersion = if ($WindowsInfo) {
    "$($WindowsInfo.Caption) (Version $($WindowsInfo.Version), Build $($WindowsInfo.BuildNumber))"
} else {
    'Unavailable'
}

Write-Host "`nSystem Information...`n" -ForegroundColor DarkGray

Write-Host "The Date and Time is: $TestDateTime" -ForegroundColor DarkGray
Write-Host "The Computer Name is: $ComputerName" -ForegroundColor DarkGray
Write-Host "The Serial Number is: $SerialNumber" -ForegroundColor DarkGray
Write-Host "The Manufacturer is: $Manufacturer" -ForegroundColor DarkGray
Write-Host "The Model is: $Model" -ForegroundColor DarkGray
Write-Host "The Windows Version is: $WindowsVersion" -ForegroundColor DarkGray

# Read the adapter selected by the active route and its matching driver.
$SystemNetworkAdapterName = 'Unavailable'
$SystemNetworkDriverProvider = 'Unavailable'
$SystemNetworkDriverVersion = 'Unavailable'
$SystemNetworkDriverDate = 'Unavailable'

try {
    $SystemNetworkAdapter = $ActiveAdapter

    if ($SystemNetworkAdapter) {
        if (-not [string]::IsNullOrWhiteSpace($SystemNetworkAdapter.InterfaceDescription)) {
            $SystemNetworkAdapterName = $SystemNetworkAdapter.InterfaceDescription.Trim()
        }
        if (-not [string]::IsNullOrWhiteSpace($SystemNetworkAdapter.PnPDeviceID)) {
            $SystemNetworkDriver = Get-CimInstance -ClassName Win32_PnPSignedDriver `
                -Filter "DeviceClass = 'NET'" -ErrorAction Stop |
                Where-Object { $_.DeviceID -eq $SystemNetworkAdapter.PnPDeviceID } |
                Select-Object -First 1

            if ($SystemNetworkDriver) {
                if (-not [string]::IsNullOrWhiteSpace($SystemNetworkDriver.DriverProviderName)) {
                    $SystemNetworkDriverProvider = $SystemNetworkDriver.DriverProviderName.Trim()
                }
                if (-not [string]::IsNullOrWhiteSpace($SystemNetworkDriver.DriverVersion)) {
                    $SystemNetworkDriverVersion = $SystemNetworkDriver.DriverVersion.Trim()
                }
                if ($SystemNetworkDriver.DriverDate -is [datetime]) {
                    $SystemNetworkDriverDate = $SystemNetworkDriver.DriverDate.ToString('yyyy-MM-dd')
                } elseif ([string]$SystemNetworkDriver.DriverDate -match '^\d{8}') {
                    $SystemNetworkDriverDate = [datetime]::ParseExact(
                        ([string]$SystemNetworkDriver.DriverDate).Substring(0, 8),
                        'yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture
                    ).ToString('yyyy-MM-dd')
                }
            }
        }
    }
} catch {
    # Keep available values and allow the diagnostic to continue.
}

Write-Host '' -ForegroundColor DarkGray
Write-Host "The $ActiveConnectionType Adapter is: $SystemNetworkAdapterName" -ForegroundColor DarkGray
Write-Host "The Driver Provider is: $SystemNetworkDriverProvider" -ForegroundColor DarkGray
Write-Host "The Driver Version is: $SystemNetworkDriverVersion" -ForegroundColor DarkGray
Write-Host "The Driver Date is: $SystemNetworkDriverDate" -ForegroundColor DarkGray



########################################## NETWORK INTERFACE PREPARATION  ##########################################

### GET BEST ROUTE IP CONFIGURATION DETAILS




### SETTING UP STANDARD VARIABLE FOR OUTPUT AS REQUIRED. DO NOT EDIT THESE VARIABLES.

$IPDetails = Get-NetIPConfiguration | where{ ($_.InterfaceIndex -eq $DefaultIfIndex)}

$InterfacesUp = @($IPDetails.InterfaceAlias)
$Geteway = $IPDetails.IPv4DefaultGateway.NextHop
$DNSServers = $IPDetails.DNSServer | Where-Object {$_.AddressFamily -eq '2'}
$DNSs = $DNSServers.ServerAddresses
$domain = (Get-WmiObject win32_computersystem).Domain
$PublicIPAddress =  $(Resolve-DnsName -Name myip.opendns.com -Server 208.67.222.220).IPAddress


######################################### WIFI / ETHERNET INFORMATION #########################################

if ($ActiveConnectionType -eq 'WiFi') {
# Uses $DefaultIfIndex from NETWORK INTERFACE PREPARATION above.
# Native WLAN data is independent of the Windows display language.

try {
    if (-not ('Netshoot.WlanReaderV1' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Netshoot {
    public static class WlanReaderV1 {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct InterfaceInfo {
            public Guid Id;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string Description;
            public int State;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct Ssid {
            public uint Length;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] Bytes;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct Association {
            public Ssid Ssid;
            public uint BssType;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] Bssid;
            public uint PhyType, PhyIndex, SignalQuality, RxRate, TxRate;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct Security {
            public int Enabled, OneXEnabled;
            public uint Authentication, Cipher;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct Connection {
            public int State, Mode;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string Profile;
            public Association Association;
            public Security Security;
        }
        public class Result {
            public bool IsWifi;
            public int State;
            public Connection? Current;
            public uint ConnectionError, ChannelError;
            public int? Channel;
        }
        [DllImport("wlanapi.dll")]
        static extern uint WlanOpenHandle(uint version, IntPtr reserved, out uint negotiated, out IntPtr handle);
        [DllImport("wlanapi.dll")]
        static extern uint WlanEnumInterfaces(IntPtr handle, IntPtr reserved, out IntPtr list);
        [DllImport("wlanapi.dll")]
        static extern uint WlanQueryInterface(IntPtr handle, ref Guid id, int opcode, IntPtr reserved,
            out uint size, out IntPtr data, out int valueType);
        [DllImport("wlanapi.dll")]
        static extern void WlanFreeMemory(IntPtr memory);
        [DllImport("wlanapi.dll")]
        static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);

        public static string SsidText(Ssid ssid) {
            if (ssid.Length > 32) return "Unavailable (invalid SSID length)";
            try {
                return new UTF8Encoding(false, true).GetString(ssid.Bytes, 0, (int)ssid.Length);
            } catch (DecoderFallbackException) {
                return "Hex: " + BitConverter.ToString(ssid.Bytes, 0, (int)ssid.Length);
            }
        }
        public static Result Read(Guid id) {
            IntPtr handle = IntPtr.Zero, list = IntPtr.Zero;
            uint version;
            uint error = WlanOpenHandle(2, IntPtr.Zero, out version, out handle);
            if (error != 0) throw new Win32Exception((int)error);
            try {
                error = WlanEnumInterfaces(handle, IntPtr.Zero, out list);
                if (error != 0) throw new Win32Exception((int)error);
                Result result = new Result();
                int count = Marshal.ReadInt32(list);
                int stride = Marshal.SizeOf(typeof(InterfaceInfo));
                for (int i = 0; i < count; i++) {
                    InterfaceInfo item = (InterfaceInfo)Marshal.PtrToStructure(
                        IntPtr.Add(list, 8 + i * stride), typeof(InterfaceInfo));
                    if (item.Id == id) { result.IsWifi = true; result.State = item.State; break; }
                }
                if (!result.IsWifi || result.State != 1) return result;
                IntPtr data = IntPtr.Zero;
                uint size;
                int valueType;
                try {
                    result.ConnectionError = WlanQueryInterface(handle, ref id, 7, IntPtr.Zero,
                        out size, out data, out valueType);
                    if (result.ConnectionError == 0) {
                        if (data == IntPtr.Zero || size < Marshal.SizeOf(typeof(Connection)))
                            result.ConnectionError = 13;
                        else result.Current = (Connection)Marshal.PtrToStructure(data, typeof(Connection));
                    }
                } finally { if (data != IntPtr.Zero) WlanFreeMemory(data); }
                data = IntPtr.Zero;
                try {
                    result.ChannelError = WlanQueryInterface(handle, ref id, 8, IntPtr.Zero,
                        out size, out data, out valueType);
                    if (result.ChannelError == 0) {
                        if (data == IntPtr.Zero || size < 4) result.ChannelError = 13;
                        else result.Channel = Marshal.ReadInt32(data);
                    }
                } finally { if (data != IntPtr.Zero) WlanFreeMemory(data); }
                return result;
            } finally {
                if (list != IntPtr.Zero) WlanFreeMemory(list);
                WlanCloseHandle(handle, IntPtr.Zero);
            }
        }
    }
}
'@
    }

    $WifiAdapter = Get-NetAdapter -InterfaceIndex $DefaultIfIndex -ErrorAction Stop
    $WifiData = [Netshoot.WlanReaderV1]::Read([guid]$WifiAdapter.InterfaceGuid)

    if ($WifiData.IsWifi) {
        Write-Host "`nWiFi Information...`n" -ForegroundColor DarkGray
        $Physical = $WifiAdapter.MacAddress -replace '-', ':'
        if ([string]::IsNullOrWhiteSpace($Physical)) { $Physical = 'Unavailable' }
        Write-Host "The adapter mac address is: $Physical" -ForegroundColor DarkGray

        if ($null -ne $WifiData.Current) {
            $Connection = $WifiData.Current
            $Association = $Connection.Association
            $SSID = [Netshoot.WlanReaderV1]::SsidText($Association.Ssid)
            $BSSID = [BitConverter]::ToString($Association.Bssid).Replace('-', ':')
            $Protocols = @{ 1='FHSS'; 2='DSSS'; 3='Infrared'; 4='802.11a'; 5='802.11b';
                6='802.11g'; 7='802.11n'; 8='802.11ac'; 9='802.11ad'; 10='802.11ax'; 11='802.11be' }
            $RadioType = $Protocols[[int]$Association.PhyType]
            if (-not $RadioType) { $RadioType = "Unknown ($($Association.PhyType))" }
            $WiFiVersion = @{ '802.11be'='Wi-Fi 7'; '802.11ax'='Wi-Fi 6';
                '802.11ac'='Wi-Fi 5'; '802.11n'='Wi-Fi 4' }
            $Generation = $WiFiVersion[$RadioType]
            if (-not $Generation) { $Generation = 'Unknown' }

            $AuthNames = @{ 1='Open'; 2='Shared key'; 3='WPA-Enterprise'; 4='WPA-Personal';
                5='WPA-None'; 6='WPA2-Enterprise'; 7='WPA2-Personal';
                8='WPA3-Enterprise 192-bit'; 9='WPA3-Personal (SAE)';
                10='Enhanced Open (OWE)'; 11='WPA3-Enterprise' }
            $Authentication = $null
            if ($Connection.Security.Authentication -le 11) { $Authentication = $AuthNames[[int]$Connection.Security.Authentication] }
            if (-not $Authentication) { $Authentication = "Unknown ($($Connection.Security.Authentication))" }
            $SignalQuality = [int]$Association.SignalQuality
            $SignalText = 'Unavailable'
            if ($SignalQuality -ge 0 -and $SignalQuality -le 100) {
                $SignalLeveldBm = ($SignalQuality / 2.0) - 100
                $SignalText = "$SignalQuality% $SignalLeveldBm dBm"
            }
            # Native WLAN link rates are reported in kilobits per second.
            $RecRate = [int]($Association.RxRate / 1000.0)
            $TransRate = [int]($Association.TxRate / 1000.0)

            Write-Host "The SSID is: $SSID" -ForegroundColor DarkGray
            Write-Host "The BSSID is: $BSSID" -ForegroundColor DarkGray
            Write-Host "The protocol is: $RadioType ( $Generation )" -ForegroundColor DarkGray
            Write-Host "The Authentication is: $Authentication" -ForegroundColor DarkGray
            $Channel = 'Unavailable'
            if ($null -ne $WifiData.Channel -and $WifiData.Channel -gt 0) { $Channel = $WifiData.Channel }
            Write-Host "The Channel is: $Channel" -ForegroundColor DarkGray
            Write-Host "The Signal is: $SignalText" -ForegroundColor DarkGray
            Write-Host "The Receive Rate is: $RecRate Mbps" -ForegroundColor DarkGray
            Write-Host "The Transmit Rate is: $TransRate Mbps" -ForegroundColor DarkGray
        } elseif ($WifiData.State -eq 1) {
            Write-Warning "WiFi connection details unavailable. Windows error: $($WifiData.ConnectionError)."
            if ($WifiData.ConnectionError -eq 5) {
                Write-Warning 'Access denied. Check Windows location permissions and organizational policies.'
            }
        } else {
            Write-Host 'WiFi connection details unavailable: adapter is not connected.' -ForegroundColor DarkGray
        }

    }
} catch {
    Write-Warning "WiFi information unavailable: $($_.Exception.Message)"
}
}
if ($ActiveConnectionType -eq 'Ethernet') {
    Write-Host "`nEthernet Information...`n" -ForegroundColor DarkGray
    $EthernetMac = $ActiveAdapter.MacAddress -replace '-', ':'
    if ([string]::IsNullOrWhiteSpace($EthernetMac)) { $EthernetMac = 'Unavailable' }
    $EthernetState = if ($ActiveAdapter.MediaConnectState -eq 1) { 'Connected' } elseif ($ActiveAdapter.MediaConnectState -eq 2) { 'Disconnected' } else { 'Unknown' }
    $EthernetDuplex = switch ($ActiveAdapter.MediaDuplexState) { 1 { 'Half duplex' } 2 { 'Full duplex' } default { 'Unknown' } }
    $EthernetRx = if ($ActiveAdapter.ReceiveLinkSpeed -gt 0) { [math]::Round($ActiveAdapter.ReceiveLinkSpeed / 1000000.0, 2).ToString() + ' Mbps' } else { 'Unavailable' }
    $EthernetTx = if ($ActiveAdapter.TransmitLinkSpeed -gt 0) { [math]::Round($ActiveAdapter.TransmitLinkSpeed / 1000000.0, 2).ToString() + ' Mbps' } else { 'Unavailable' }
    Write-Host "The adapter mac address is: $EthernetMac" -ForegroundColor DarkGray
    Write-Host "The Link State is: $EthernetState" -ForegroundColor DarkGray
    Write-Host "The Duplex Mode is: $EthernetDuplex" -ForegroundColor DarkGray
    Write-Host "The Receive Rate is: $EthernetRx" -ForegroundColor DarkGray
    Write-Host "The Transmit Rate is: $EthernetTx" -ForegroundColor DarkGray
}

####################################################################################################################


############################################## COLLECTING INFORMATION ##############################################

Write-Host "`nCollecting Information...`n" -ForegroundColor DarkGray

Write-Host "The default interface is $DefaultInterface" -ForegroundColor DarkGray

### INTERFACES UP

foreach ($InterfaceUp in $InterfacesUp)
    {
    $IfUpDetails = Get-NetIPConfiguration -InterfaceAlias $InterfaceUp
    $IfUpPrefixOrigin = $IfUpDetails.IPv4Address.PrefixOrigin
    $IfUpIPAddress = $IfUpDetails.IPv4Address.IPAddress
    $IfUpPrefixLength = $IfUpDetails.IPv4Address.PrefixLength
    $IfUpNextHop = $IfUpDetails.IPv4DefaultGateway.NextHop

    Write-Host "Interface $InterfaceUp is UP, $IfUpPrefixOrigin, $IfUpIPAddress/$IfUpPrefixLength $IfUpNextHop" -ForegroundColor DarkGray
    }

### PRINT PUBLIC IP ADDRESS 

Write-Host "The Public IP Address is: $PublicIPAddress" -ForegroundColor DarkGray`n


### PRINT CPU USAGE

$cpuAverage = (Get-WmiObject -Class win32_processor -ErrorAction Stop | Measure-Object -Property LoadPercentage -Average | Select-Object Average).Average

Write-Host "The CPU Average is: $cpuAverage" -ForegroundColor DarkGray


### PRINT RAM USAGE 

$CompObject =  Get-WmiObject -Class WIN32_OperatingSystem
$RAM = [math]::Round((($CompObject.TotalVisibleMemorySize - $CompObject.FreePhysicalMemory)/1024/1024),2)

Write-Host "The RAM usage is: $RAM GB" -ForegroundColor DarkGray


####################################################################################################################


################################################## STARTING TESTS ##################################################

Write-Host "`nStarting Tests...`n" -ForegroundColor DarkGray

# TRACEROUTE PING TEST

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

### TEST DNS CONNECTIVITY

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

### PUBLIC DNS STATUS

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


### LOCAL DOMAIN JOINED STATUS

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



### DNS RESOLUTION TEST

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
 
 
### PORT TEST TO PUBLIC SITES ON PORT 80 AND 443

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



################################################ RUNNING SPEED TEST ################################################

Write-Host "`nRunning Speed Tests..." -ForegroundColor DarkGray

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
        Write-Host "Speed Test #$TestNumber...`n" -ForegroundColor DarkGray

        # Mostrar directamente el formato nativo de Ookla.
        & $SpeedTestPath --accept-license --accept-gdpr
        $SpeedTestExitCode = $LASTEXITCODE

        if ($SpeedTestExitCode -ne 0) {
            throw "Speed Test #$TestNumber fallo con codigo $SpeedTestExitCode."
        }
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


################################################## DELETING FILES ##################################################

Remove-Item -Path .\ts.ps1


####################################### NETWORK CONNECTIVITY TESTS COMPLETED #######################################

Write-Host   "`nNetwork Connectivity Tests Completed...`n" -ForegroundColor DarkGray


######################################### COLLECTING WIFI / ETHERNET LOGS #########################################

if ($ActiveConnectionType -eq 'WiFi') {
try {
    $WiFiLogEndTime = Get-Date
    $WiFiEvents = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
            StartTime = $WiFiLogEndTime.AddHours(-24)
            EndTime   = $WiFiLogEndTime
        } -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated
    )

    if ($WiFiEvents.Count -gt 0) {
        Write-Host "`nCollecting WiFi Logs...`n" -ForegroundColor DarkGray
        Write-Host "WiFi Events - Last 24 Hours...`n" -ForegroundColor DarkGray

        $WiFiSummaryText = $WiFiEvents |
            Select-Object @{
                Name = 'Date and Time'
                Expression = { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }
            }, Id, @{
                Name = 'Level'
                Expression = { $_.LevelDisplayName }
            }, @{
                Name = 'Message'
                Expression = { ($_.Message -split '\r?\n')[0] }
            } |
            Format-Table -AutoSize -Wrap |
            Out-String

        Write-Host ([regex]::Replace($WiFiSummaryText, '\x1B\[[0-9;:]*m', '').TrimEnd()) -ForegroundColor DarkGray

        $WiFiIssues = @(
            $WiFiEvents | Where-Object { $_.Level -in @(1, 2, 3) }
        )

        if ($WiFiIssues.Count -gt 0) {
            Write-Host "`nWiFi Errors and Warnings - Full Details...`n" -ForegroundColor DarkGray
            $WiFiDetailsText = $WiFiIssues |
                Format-List TimeCreated, Id, LevelDisplayName, Message |
                Out-String

            Write-Host ([regex]::Replace($WiFiDetailsText, '\x1B\[[0-9;:]*m', '').TrimEnd()) -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "`nNo hubo logs de WiFi en las ultimas 24 horas." -ForegroundColor DarkGray
    }
}
catch {
    Write-Warning "No fue posible consultar los logs de WiFi."
}
}
if ($ActiveConnectionType -eq 'Ethernet') {
    # Require the current adapter identity. Do not attribute every System or
    # NetworkProfile event to Ethernet merely because Ethernet is active now.
    $EthernetIdentifiers = @(
        [string]$ActiveAdapter.InterfaceGuid
        [string]$ActiveAdapter.PnPDeviceID
        [string]$ActiveAdapter.InterfaceDescription
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim().Trim('{', '}') }
    $EthernetLogEnd = Get-Date
    $EthernetEvents = @(
        foreach ($EthernetLog in @('Microsoft-Windows-Wired-AutoConfig/Operational', 'System', 'Microsoft-Windows-NetworkProfile/Operational')) {
            try {
                Get-WinEvent -FilterHashtable @{
                    LogName = $EthernetLog
                    StartTime = $EthernetLogEnd.AddHours(-24)
                    EndTime = $EthernetLogEnd
                } -ErrorAction SilentlyContinue | Where-Object {
                    $EthernetEvent = $_
                    $EthernetMatches = $false
                    try {
                        $EthernetXml = [xml]$EthernetEvent.ToXml()
                        $EthernetValues = @($EthernetXml.SelectNodes('//*[local-name()="EventData"]/* | //*[local-name()="UserData"]//*[not(*)]') | ForEach-Object { $_.InnerText })
                        $EthernetValues += [string]$EthernetEvent.Message
                        foreach ($EthernetIdentity in $EthernetIdentifiers) {
                            foreach ($EthernetValue in $EthernetValues) {
                                if ($EthernetValue.IndexOf($EthernetIdentity, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                    $EthernetMatches = $true
                                    break
                                }
                            }
                            if ($EthernetMatches) { break }
                        }
                    } catch { }
                    $EthernetMatches
                }
            } catch { }
        }
    ) | Sort-Object TimeCreated
    $EthernetEvents = @($EthernetEvents)
    if ($EthernetEvents.Count -gt 0) {
        Write-Host "`nCollecting Ethernet Logs...`n" -ForegroundColor DarkGray
        Write-Host "Ethernet Events - Last 24 Hours...`n" -ForegroundColor DarkGray
        $EthernetSummary = $EthernetEvents | Select-Object @{
            Name='Date and Time'; Expression={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}
        }, Id, @{Name='Level';Expression={$_.LevelDisplayName}}, ProviderName, @{
            Name='Message';Expression={($_.Message -split '\r?\n')[0]}
        } | Format-Table -AutoSize -Wrap | Out-String
        Write-Host ([regex]::Replace($EthernetSummary, '\x1B\[[0-9;:]*m', '').TrimEnd()) -ForegroundColor DarkGray

        $EthernetIssues = @($EthernetEvents | Where-Object { $_.Level -in @(1,2,3) })
        if ($EthernetIssues.Count -gt 0) {
            Write-Host "`nEthernet Errors and Warnings - Full Details...`n" -ForegroundColor DarkGray
            $EthernetDetails = $EthernetIssues | Format-List TimeCreated, Id, ProviderName, LevelDisplayName, Message | Out-String
            Write-Host ([regex]::Replace($EthernetDetails, '\x1B\[[0-9;:]*m', '').TrimEnd()) -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "`nNo hubo logs de Ethernet en las ultimas 24 horas." -ForegroundColor DarkGray
    }
}





################################################## SAVING OUTPUT  ##################################################

} catch {
    Write-Warning "Diagnostic stopped: $($_.Exception.Message)"
} finally {
    if ($DiagnosticReportStarted) {
        try {
            Stop-Transcript -ErrorAction Stop | Out-Null
            $DiagnosticReportText = [IO.File]::ReadAllText($DiagnosticReportTemp + '.log')
            # Keep diagnostic output; omit the localized transcript header/footer.
            $DiagnosticReportFirst = $DiagnosticReportText.IndexOf('Starting Network Connectivity Test...')
            if ($DiagnosticReportFirst -ge 0) {
                $DiagnosticReportText = $DiagnosticReportText.Substring($DiagnosticReportFirst)
                $DiagnosticReportText = [regex]::Split(
                    $DiagnosticReportText, '(?m)^\*{20,}\r?$'
                )[0].TrimEnd()
            }

            Remove-Item -LiteralPath ($DiagnosticReportTemp + '.log') -Force -ErrorAction SilentlyContinue

            try {
                $DiagnosticReportBytes = [Text.Encoding]::UTF8.GetBytes($DiagnosticReportText)
                $DiagnosticPcName = ($env:COMPUTERNAME -replace '[^A-Za-z0-9_-]', '_')
                if ([string]::IsNullOrWhiteSpace($DiagnosticPcName)) {
                    $DiagnosticPcName = 'UNKNOWN-PC'
                }
                if ($DiagnosticPcName.Length -gt 64) {
                    $DiagnosticPcName = $DiagnosticPcName.Substring(0, 64)
                }

                $DiagnosticBasicToken = [Convert]::ToBase64String(
                    [Text.Encoding]::ASCII.GetBytes(
                        "$DiagnosticUploadUsername`:$DiagnosticUploadPassword"
                    )
                )
                $DiagnosticUploadHeaders = @{
                    'Authorization' = "Basic $DiagnosticBasicToken"
                    'X-PC-Name' = $DiagnosticPcName
                    'X-File-Name' = $DiagnosticReportName
                }

                $DiagnosticUploadResponse = Invoke-RestMethod `
                    -Uri $DiagnosticUploadUri `
                    -Method Post `
                    -Headers $DiagnosticUploadHeaders `
                    -Body $DiagnosticReportBytes `
                    -ContentType 'text/plain; charset=utf-8' `
                    -TimeoutSec 120 `
                    -ErrorAction Stop

                $UploadedReportName = [string]$DiagnosticUploadResponse.archivo
                if ([string]::IsNullOrWhiteSpace($UploadedReportName)) {
                    throw 'El servidor no devolvio el nombre del archivo guardado.'
                }

                Write-Host "`nEl reporte de texto fue enviado correctamente." -ForegroundColor DarkGray
                Write-Host "`nPor favor, envie este codigo al Departamento de Soporte: $UploadedReportName" -ForegroundColor Gray
            }
            catch {
                Write-Warning "`nNo fue posible enviar el reporte de texto al servidor: $($_.Exception.Message)"
                $DiagnosticErrorDetails = [string]$_.ErrorDetails.Message
                if (-not [string]::IsNullOrWhiteSpace($DiagnosticErrorDetails)) {
                    try {
                        $DiagnosticServerError = $DiagnosticErrorDetails | ConvertFrom-Json -ErrorAction Stop
                        if (-not [string]::IsNullOrWhiteSpace($DiagnosticServerError.error)) {
                            Write-Host "`nDetalle del servidor: $($DiagnosticServerError.error)" -ForegroundColor DarkGray
                        }
                    }
                    catch {
                        Write-Host "`nDetalle del servidor: $DiagnosticErrorDetails" -ForegroundColor DarkGray
                    }
                }
                Write-Host "`nCodigo local del reporte (no enviado): $DiagnosticReportName" -ForegroundColor DarkGray
            }

        } catch {
            Remove-Item -LiteralPath ($DiagnosticReportTemp + '.log') -Force -ErrorAction SilentlyContinue
            Write-Warning "`nNo fue posible procesar el reporte de texto: $($_.Exception.Message)"
        }
    }
}


####################################################### END  ##################################################
