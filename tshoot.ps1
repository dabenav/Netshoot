####################################################################################################################
#  Date: 09 Sep 2026
#  Name: Network Troubleshooting Script
#  Task: To verify the network connectivity performance and errors
#  By: Daniel Benavides
####################################################################################################################

####################################### PDF Report Capture ########################################

$DiagnosticReportStamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$DiagnosticReportName = "$env:COMPUTERNAME-$DiagnosticReportStamp.pdf"
$DiagnosticReportTemp = Join-Path ([IO.Path]::GetTempPath()) (
    'NetworkDiagnostic-' + [guid]::NewGuid().ToString('N')
)
$DiagnosticReportStarted = $false
try {
    Start-Transcript -LiteralPath ($DiagnosticReportTemp + '.log') -ErrorAction Stop | Out-Null
    $DiagnosticReportStarted = $true
} catch {
    Write-Warning "PDF report capture could not start: $($_.Exception.Message)"
}

try {


Write-Host "`nStarting Network Connectivity test....." -ForegroundColor DarkGray


########################## Edit these variables as needed ###############################

$PublicDNS = "8.8.8.8"
$PublicSites = "cisco.com"
$pingCount = 8

####################################### System Information ########################################

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

Write-Host "`nSystem Information.....`n" -ForegroundColor DarkGray

Write-Host "The Date and Time is: $TestDateTime" -ForegroundColor DarkGray
Write-Host "The Computer Name is: $ComputerName" -ForegroundColor DarkGray
Write-Host "The Serial Number is: $SerialNumber" -ForegroundColor DarkGray
Write-Host "The Manufacturer is: $Manufacturer" -ForegroundColor DarkGray
Write-Host "The Model is: $Model" -ForegroundColor DarkGray
Write-Host "The Windows Version is: $WindowsVersion" -ForegroundColor DarkGray


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

###############################################################################################################
####################################### WiFi Settings ########################################

# Requires $DefaultIfIndex from the existing Collecting Information section.
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
###############################################################################################################


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



####################################### Saving Output ########################################


} catch {
    Write-Warning "Diagnostic stopped: $($_.Exception.Message)"
} finally {
    if ($DiagnosticReportStarted) {
        try {
            Stop-Transcript -ErrorAction Stop | Out-Null
            $DiagnosticReportText = [IO.File]::ReadAllText($DiagnosticReportTemp + '.log')
            # Keep diagnostic output; omit the localized transcript header/footer.
            $DiagnosticReportFirst = $DiagnosticReportText.IndexOf('Starting Network Connectivity test.....')
            if ($DiagnosticReportFirst -ge 0) {
                $DiagnosticReportText = $DiagnosticReportText.Substring($DiagnosticReportFirst)
                $DiagnosticReportText = [regex]::Split(
                    $DiagnosticReportText, '(?m)^\*{20,}\r?$'
                )[0].TrimEnd()
            }

            Add-Type -AssemblyName System.Drawing -ErrorAction Stop
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            if (-not ('Netshoot.PdfReportV1' -as [type])) {
                Add-Type -ReferencedAssemblies System.Drawing, System.Windows.Forms -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Netshoot {
    // Render Unicode text with Windows fonts and embed pages in a real PDF.
    // No browser, Office installation, printer driver or downloaded library is required.
    public static class PdfReportV1 {
        static void Put(Stream stream, string text) {
            byte[] bytes = Encoding.ASCII.GetBytes(text);
            stream.Write(bytes, 0, bytes.Length);
        }
        static void StartObject(Stream stream, List<long> offsets, int id) {
            while (offsets.Count <= id) offsets.Add(0);
            offsets[id] = stream.Position;
            Put(stream, id.ToString(CultureInfo.InvariantCulture) + " 0 obj\n");
        }
        static List<string> Wrap(string text, Graphics graphics, Font font, float width, StringFormat format) {
            List<string> lines = new List<string>();
            foreach (string raw in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n')) {
                string line = raw.Replace("\t", "    ");
                if (line.Length == 0) { lines.Add(""); continue; }
                while (line.Length > 0) {
                    int low = 1, high = line.Length, fit = 0;
                    while (low <= high) {
                        int middle = low + (high - low) / 2;
                        if (graphics.MeasureString(line.Substring(0, middle), font, Int32.MaxValue, format).Width <= width) {
                            fit = middle; low = middle + 1;
                        } else high = middle - 1;
                    }
                    fit = Math.Max(1, fit);
                    if (fit < line.Length && fit > 1 && Char.IsHighSurrogate(line[fit - 1])) fit--;
                    lines.Add(line.Substring(0, fit));
                    line = line.Substring(fit);
                }
            }
            return lines;
        }
        public static void Create(string text, string path) {
            const int width = 1530, height = 1980, margin = 100, top = 140;
            const float lineHeight = 33;
            const int perPage = 51;
            using (Bitmap bitmap = new Bitmap(width, height))
            using (Graphics graphics = Graphics.FromImage(bitmap))
            using (Font body = new Font("Consolas", 23.75f, FontStyle.Regular, GraphicsUnit.Pixel))
            using (Font title = new Font("Segoe UI", 27.5f, FontStyle.Bold, GraphicsUnit.Pixel))
            using (Font footer = new Font("Segoe UI", 20, FontStyle.Regular, GraphicsUnit.Pixel))
            using (StringFormat format = (StringFormat)StringFormat.GenericTypographic.Clone()) {
                bitmap.SetResolution(180, 180);
                graphics.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
                format.FormatFlags |= StringFormatFlags.MeasureTrailingSpaces;
                List<string> lines = Wrap(text, graphics, body, width - 2 * margin, format);
                int pageCount = Math.Max(1, (lines.Count + perPage - 1) / perPage);
                ImageCodecInfo jpeg = null;
                foreach (ImageCodecInfo codec in ImageCodecInfo.GetImageEncoders())
                    if (codec.MimeType == "image/jpeg") jpeg = codec;
                if (jpeg == null) throw new InvalidOperationException("Windows JPEG encoder is unavailable.");
                using (FileStream output = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
                    List<long> offsets = new List<long>();
                    offsets.Add(0);
                    Put(output, "%PDF-1.4\n");
                    StartObject(output, offsets, 1);
                    Put(output, "<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
                    StartObject(output, offsets, 2);
                    Put(output, "<< /Type /Pages /Count " + pageCount + " /Kids [");
                    for (int page = 0; page < pageCount; page++) Put(output, (3 + page * 3) + " 0 R ");
                    Put(output, "] >>\nendobj\n");
                    for (int page = 0; page < pageCount; page++) {
                        graphics.Clear(Color.White);
                        graphics.DrawString("Network Connectivity Test", title, Brushes.Black, margin, 60);
                        for (int i = 0; i < perPage && page * perPage + i < lines.Count; i++)
                            graphics.DrawString(lines[page * perPage + i], body, Brushes.Black,
                                margin, top + i * lineHeight, format);
                        graphics.DrawString("Page " + (page + 1) + " / " + pageCount,
                            footer, Brushes.DimGray, margin, height - 90);
                        byte[] image;
                        using (MemoryStream memory = new MemoryStream())
                        using (EncoderParameters parameters = new EncoderParameters(1)) {
                            parameters.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 95L);
                            bitmap.Save(memory, jpeg, parameters);
                            image = memory.ToArray();
                        }
                        int id = 3 + page * 3;
                        StartObject(output, offsets, id);
                        Put(output, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
                            "/Resources << /XObject << /Report " + (id + 2) + " 0 R >> >> " +
                            "/Contents " + (id + 1) + " 0 R >>\nendobj\n");
                        string content = "q\n612 0 0 792 0 0 cm\n/Report Do\nQ\n";
                        StartObject(output, offsets, id + 1);
                        Put(output, "<< /Length " + Encoding.ASCII.GetByteCount(content) + " >>\nstream\n" +
                            content + "endstream\nendobj\n");
                        StartObject(output, offsets, id + 2);
                        Put(output, "<< /Type /XObject /Subtype /Image /Width 1530 /Height 1980 " +
                            "/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length " +
                            image.Length + " >>\nstream\n");
                        output.Write(image, 0, image.Length);
                        Put(output, "\nendstream\nendobj\n");
                    }
                    long xref = output.Position;
                    Put(output, "xref\n0 " + offsets.Count + "\n0000000000 65535 f \n");
                    for (int i = 1; i < offsets.Count; i++)
                        Put(output, offsets[i].ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n");
                    Put(output, "trailer\n<< /Size " + offsets.Count + " /Root 1 0 R >>\nstartxref\n" +
                        xref.ToString(CultureInfo.InvariantCulture) + "\n%%EOF\n");
                }
            }
        }
        public static string ChoosePath(string fileName) {
            string selected = null;
            Exception failure = null;
            Thread dialogThread = new Thread(delegate() {
                try {
                    using (SaveFileDialog dialog = new SaveFileDialog()) {
                        dialog.Title = "Save Network Test Report";
                        dialog.Filter = "PDF report (*.pdf)|*.pdf";
                        dialog.FileName = fileName;
                        dialog.DefaultExt = "pdf";
                        dialog.AddExtension = true;
                        dialog.OverwritePrompt = true;
                        dialog.CheckPathExists = true;
                        dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                        if (dialog.ShowDialog() == DialogResult.OK) selected = dialog.FileName;
                    }
                } catch (Exception error) { failure = error; }
            });
            dialogThread.SetApartmentState(ApartmentState.STA);
            dialogThread.Start();
            dialogThread.Join();
            if (failure != null) throw new InvalidOperationException("Save dialog failed.", failure);
            return selected;
        }
    }
}
'@
            }
            [Netshoot.PdfReportV1]::Create($DiagnosticReportText, $DiagnosticReportTemp + '.pdf')
            Remove-Item -LiteralPath ($DiagnosticReportTemp + '.log') -ErrorAction SilentlyContinue
            $DiagnosticReportTarget = [Netshoot.PdfReportV1]::ChoosePath($DiagnosticReportName)
            if (-not [string]::IsNullOrWhiteSpace($DiagnosticReportTarget)) {
                Copy-Item -LiteralPath ($DiagnosticReportTemp + '.pdf') -Destination $DiagnosticReportTarget -Force -ErrorAction Stop
                Remove-Item -LiteralPath ($DiagnosticReportTemp + '.pdf') -ErrorAction SilentlyContinue
                Write-Host "`nThe PDF report was saved to: $DiagnosticReportTarget" -ForegroundColor DarkGray
            } else {
                Write-Host "`nSave cancelled. The PDF report is available at: $DiagnosticReportTemp.pdf" -ForegroundColor DarkGray
            }
        } catch {
            Write-Warning "PDF report could not be saved: $($_.Exception.Message)"
            if (Test-Path -LiteralPath ($DiagnosticReportTemp + '.pdf')) {
                Write-Host "Recovery file (may be incomplete): $DiagnosticReportTemp.pdf" -ForegroundColor DarkGray
            }
        }
    }
}


########################################### END ###############################################

