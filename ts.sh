#!/bin/bash

######################################################################
#  Date: 09 Sep 2026 11:08:30 -05:00 (America/Bogota)                #
#  Name: Network Troubleshooting Script                              #
#  Task: To verify the network connectivity performance and errors   #
#  By: Dabenav                                             #
######################################################################

# Network diagnostics for macOS. Run with /bin/bash, without sudo.
# Deletes this script and its private temporary directory on exit.
# No Homebrew, Python or PowerShell required.

################################################## CONFIGURATION ###################################################

umask 077
export LC_ALL=C
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
if [ "$(uname -s)" != Darwin ]; then
    printf 'Este script requiere macOS.\n' >&2
    exit 1
fi


############################################ TEMPORARY FILE PREPARATION ############################################

script_path=''
if [ -f "$0" ]; then
    script_path="$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")"
fi
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/netshoot.XXXXXXXX") || exit 1

############################################## DELETING FILES ON EXIT ##############################################

cleanup() {
    # Only remove the directory created by mktemp and this exact script.
    if [ -n "$work_dir" ] && [ -d "$work_dir" ]; then
        rm -rf -- "$work_dir"
    fi
    if [ -n "$script_path" ]; then rm -f -- "$script_path"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP


############################################ TEXT REPORT CONFIGURATION #############################################

upload_uri='http://150.136.170.102/upload'
report="$work_dir/report.txt"
pc_name=$(scutil --get LocalHostName 2>/dev/null || hostname -s)
pc_name=$(printf '%s' "$pc_name" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-64)
[ -n "$pc_name" ] || pc_name=UNKNOWN-MAC
# JXA supplies local time including real milliseconds (BSD date has no %N).
stamp=$(osascript -l JavaScript -e 'var d=new Date(); function p(n,w){return ("0000"+n).slice(-w)}; d.getFullYear()+"-"+p(d.getMonth()+1,2)+"-"+p(d.getDate(),2)+"_"+p(d.getHours(),2)+"-"+p(d.getMinutes(),2)+"-"+p(d.getSeconds(),2)+"-"+p(d.getMilliseconds(),3)' 2>/dev/null)
if [ -z "$stamp" ]; then
    printf 'No fue posible generar la fecha del reporte.\n' >&2
    exit 1
fi
report_name="${pc_name}_${stamp}.txt"


############################################ OUTPUT AND PING FUNCTIONS #############################################

section() { printf '\n%s\n\n' "$1"; }
ping_test() {
    local label="$1" target="$2" rc
    [ -n "$target" ] || return 0
    case "$target" in
        *:*) /sbin/ping6 -n -c 8 "$target" > "$work_dir/ping" 2>&1 ;;
        *) /sbin/ping -n -c 8 -W 1000 "$target" > "$work_dir/ping" 2>&1 ;;
    esac
    rc=$?
    awk -v label="$label" -v target="$target" -v rc="$rc" '
        function number(n, s) {s=sprintf("%.2f",n);sub(/0+$/,"",s);sub(/[.]$/,"",s);return s}
        /packets transmitted/ { for(i=1;i<=NF;i++) if($i=="packet" && $(i+1)=="loss") loss=number($(i-1)+0) "%" }
        /min\/avg\/max/ { split($0,a," = "); split(a[2],v,"/"); times=number(v[1]) "/" number(v[2]) "/" number(v[3]) }
        END {
            if(loss=="") printf "Ping test to %s %s FAILED (command exit %s)\n",label,target,rc;
            else printf "Ping test to %s %s response time Min/Avg/Max = %s ms, Packet Loss %s\n",label,target,(times=="" ? "/0/" : times),loss;
        }' "$work_dir/ping"
}


##################################### WIFI / ETHERNET LOG COLLECTION FUNCTION ######################################

collect_logs() {
    local label="$1" predicate="$2"
    # Keep the full 24-hour query; filter and group before printing.
    if /usr/bin/log show --last 24h --style ndjson --info --predicate "$predicate" \
        > "$work_dir/events" 2> "$work_dir/log-errors"; then
        cat > "$work_dir/format-logs.js" <<'JAVASCRIPT'
function formatLogs(text) {
    var groups = Object.create(null), invalid = 0, relevant = 0;
    // Match WiFi/Ethernet state transitions and authentication, not generic
    // libnetwork connection objects, DNS requests or telemetry messages.
    var transitions = /\b(disconnect(?:ed|ing|ion)?|deauth(?:entication|enticated)?|disassoc(?:iation|iated)?|reassoc(?:iation|iated)?|associated|associating|association|authentication|authenticate(?:d)?|authenticating|EAPOL|802\.1[xX]|WPA[23]?|handshake|roam(?:ing|ed)?)\b|\b(?:link|connection|network)\s+(?:is\s+)?(?:up|down|lost|established|failed|disconnected)\b|\b(?:joined|joining|connected|connecting)\s+(?:to\s+)?(?:SSID|BSSID|network|AP)\b/i;
    text.split(/\r?\n/).forEach(function (line) {
        if (!line.trim()) return;
        var e;
        try { e = JSON.parse(line); } catch (_) { invalid++; return; }
        if (typeof e.eventMessage !== 'string') return;
        var level = String(e.messageType || 'Unknown');
        var message = e.eventMessage.replace(/\s+/g, ' ').trim();
        if (!/^(error|fault)$/i.test(level) && !transitions.test(message)) return;
        relevant++;
        // Group identical messages at the same level, keeping source identity
        // in the key to avoid conflating separate components.
        var key = JSON.stringify([level, message, e.processImagePath || '', e.subsystem || '', e.category || '']);
        var stamp = String(e.timestamp || 'Fecha no disponible');
        if (!groups[key]) groups[key] = { first: stamp, last: stamp, level: level, message: message, count: 0 };
        var g = groups[key];
        g.count++;
        if (stamp < g.first) g.first = stamp;
        if (stamp > g.last) g.last = stamp;
    });
    var rows = Object.keys(groups).map(function (key) { return groups[key]; });
    rows.sort(function (a, b) { return a.first < b.first ? -1 : a.first > b.first ? 1 : 0; });
    var output = [];
    if (rows.length) {
        output.push('Fecha | Nivel | Mensaje');
        rows.forEach(function (g) {
            var date = g.first === g.last ? g.first : g.first + ' hasta ' + g.last;
            output.push(date + ' | ' + g.level + ' | ' + g.message +
                (g.count > 1 ? ' [Ocurrencias: ' + g.count + ']' : ''));
        });
    } else {
        output.push('No se encontraron errores, fallos ni eventos relevantes de conexion o autenticacion en los registros consultados.');
    }
    if (invalid) output.push('Advertencia: ' + invalid + ' lineas no pudieron interpretarse; el resumen puede estar incompleto.');
    return output.join('\n');
}
function run(args) {
    ObjC.import('Foundation');
    var content = $.NSString.stringWithContentsOfFileEncodingError(args[0], $.NSUTF8StringEncoding, null);
    if (!content) throw new Error('No fue posible leer los eventos.');
    return formatLogs(ObjC.unwrap(content));
}
JAVASCRIPT
        if ! osascript -l JavaScript "$work_dir/format-logs.js" "$work_dir/events" \
            > "$work_dir/events-summary" 2> "$work_dir/format-errors"; then
            printf '\nNo fue posible resumir los logs de %s.\n' "$label"
        elif grep -q '"eventMessage"' "$work_dir/events"; then
            section "$label Events - Last 24 Hours (macOS unified log)"
            cat "$work_dir/events-summary"
        else
            printf '\nNo hubo logs de %s en las ultimas 24 horas.\n' "$label"
            if grep -q '^Advertencia:' "$work_dir/events-summary"; then
                cat "$work_dir/events-summary"
            fi
        fi
        if [ -s "$work_dir/log-errors" ]; then
            printf 'La consulta de logs devolvio advertencias; la cobertura puede ser parcial.\n'
        fi
    else
        printf '\nNo fue posible consultar los logs de %s con los permisos actuales.\n' "$label"
    fi
}


############################################### SPEED TEST FUNCTION ################################################

run_speedtest() {
    local url test_number test_exit
    url='https://github.com/dabenav/Netshoot/raw/refs/heads/main/speedtest'
    # Direct executable: the former archive SHA-256 does not apply.
    section 'Running Speed Tests...'
    if ! curl -fLsS --connect-timeout 15 --max-time 120 "$url" -o "$work_dir/speedtest" 2> "$work_dir/download-error"; then
        printf 'No fue posible descargar Speedtest.\n'
        return
    fi
    if [ ! -s "$work_dir/speedtest" ]; then
        printf 'El ejecutable de Speedtest descargado esta vacio.\n'
        return
    fi
    chmod 700 "$work_dir/speedtest"
    if ! "$work_dir/speedtest" --version; then
        printf 'Este ejecutable de Speedtest no pudo iniciarse en este Mac.\n'
        return
    fi
    for test_number in 1 2; do
        [ "$test_number" -eq 1 ] || sleep 3
        section "Speed Test #$test_number..."
        # Native human-readable output; omit animated progress from the TXT.
        "$work_dir/speedtest" --accept-license --accept-gdpr --progress=no
        test_exit=$?
        if [ "$test_exit" -ne 0 ]; then
            printf 'No fue posible completar la prueba. Codigo de salida: %s\n' "$test_exit"
        fi
    done
}


######################################## STARTING NETWORK CONNECTIVITY TEST ########################################

diagnose() {
    local route_info iface gateway hardware_port connection_type dns server port hop number
    local mac state ip mask prefix method service public_ip firmware media speed duplex ipv6
    section 'Starting Network Connectivity Test...'

################################################ SYSTEM INFORMATION ################################################

    section 'System Information...'
    printf 'The Date and Time is: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z' | sed 's/\([+-][0-9][0-9]\)\([0-9][0-9]\)$/\1:\2/')"
    printf 'The Computer Name is: %s\n' "$pc_name"
    printf 'The Serial Number is: %s\n' "$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/{print $(NF-1)}')"
    printf 'The Manufacturer is: Apple\n'
    printf 'The Model is: %s\n' "$(sysctl -n hw.model)"
    printf 'The macOS Version is: %s %s (Build %s)\n' "$(sw_vers -productName)" "$(sw_vers -productVersion)" "$(sw_vers -buildVersion)"

########################################## NETWORK INTERFACE PREPARATION ###########################################

    route_info=$(route -n get 8.8.8.8 2>/dev/null)
    iface=$(printf '%s\n' "$route_info" | awk '/interface:/{print $2; exit}')
    gateway=$(printf '%s\n' "$route_info" | awk '/gateway:/{print $2; exit}')
    hardware_port=$(networksetup -listallhardwareports | awk -v dev="$iface" '/^Hardware Port:/{sub(/^Hardware Port: /, ""); name=$0} /^Device:/{if ($2==dev) print name}')
    case "$hardware_port" in
        *Wi-Fi*|*AirPort*) connection_type=WiFi ;;
        *Ethernet*|*LAN*) connection_type=Ethernet ;;
        *) connection_type=Network ;;
    esac
    : > "$work_dir/interface"
    if [ -n "$iface" ]; then ifconfig "$iface" > "$work_dir/interface" 2>/dev/null; fi
    mac=$(awk '/^[ \t]*ether /{print toupper($2);exit}' "$work_dir/interface")
    state=$(awk '/status:/{print ($2=="active" ? "Connected" : "Disconnected");exit}' "$work_dir/interface")
    ip=$(awk '$1=="inet"{print $2;exit}' "$work_dir/interface")
    mask=$(awk '$1=="inet"{for(i=1;i<=NF;i++) if($i=="netmask") {print $(i+1);exit}}' "$work_dir/interface")
    prefix=''
    if [[ "$mask" =~ ^0x[0-9a-fA-F]+$ ]]; then
        prefix=$(awk -v mask="$mask" 'BEGIN {sub(/^0x/,"",mask); n=0; for(i=1;i<=length(mask);i++){c=tolower(substr(mask,i,1)); p=index("0123456789abcdef",c)-1; for(j=0;j<4;j++){n+=p%2;p=int(p/2)}} print n}')
    fi
    service=$(networksetup -listnetworkserviceorder | awk -v dev="$iface" '/^\([0-9]+\)/ {name=$0;sub(/^\([0-9]+\) /,"",name)} index($0,"Device: " dev ")") && dev!="" {print name;exit}')
    method=Unknown
    if [ -n "$service" ]; then
        networksetup -getinfo "$service" > "$work_dir/service" 2>/dev/null
        if grep -q '^DHCP Configuration' "$work_dir/service"; then method=DHCP
        elif grep -q '^Manual Configuration' "$work_dir/service"; then method=Manual
        elif grep -q '^BOOTP Configuration' "$work_dir/service"; then method=BOOTP
        fi
    fi
    printf '\nThe %s Adapter is: %s (%s)\n' "$connection_type" "${hardware_port:-Unavailable}" "${iface:-Unavailable}"
    if [ "$connection_type" = WiFi ]; then
        # Restrict the text parser to the selected interface, excluding awdl0.
        system_profiler SPAirPortDataType -detailLevel basic -timeout 30 > "$work_dir/wifi-all" 2>/dev/null
        awk -v dev="$iface" '
            $0 ~ "^        " dev ":$" {active=1;next}
            active && /^        [^ ]/ {exit}
            active {print}
        ' "$work_dir/wifi-all" > "$work_dir/wifi"
        firmware=$(sed -n 's/^[[:space:]]*Firmware Version: //p' "$work_dir/wifi")
        printf 'The Firmware Version is: %s\n' "${firmware:-Unavailable}"
    fi

########################################### WIFI / ETHERNET INFORMATION ############################################

    section "$connection_type Information..."
    printf 'The adapter mac address is: %s\n' "${mac:-Unavailable}"
    if [ "$connection_type" = WiFi ]; then
        awk '
            /Current Network Information:/ {current=1;next}
            current && !ssid && /^            [^ ]/ {ssid=$0;sub(/^[ \t]+/,"",ssid);sub(/:$/,"",ssid);next}
            current && /PHY Mode:/ {phy=$0;sub(/^.*PHY Mode: /,"",phy)}
            current && /Channel:/ {channel=$0;sub(/^.*Channel: /,"",channel)}
            current && /Security:/ {security=$0;sub(/^.*Security: /,"",security)}
            current && /Signal \/ Noise:/ {s=$0;sub(/^.*Signal \/ Noise: /,"",s);split(s,v," / ");signal=v[1];noise=v[2]}
            current && /Transmit Rate:/ {rate=$0;sub(/^.*Transmit Rate: /,"",rate)}
            current && /BSSID:/ {bssid=$0;sub(/^.*BSSID: /,"",bssid)}
            function val(s){return s=="" ? "Unavailable" : s}
            END {
                gen=(phy=="802.11ax" ? "Wi-Fi 6" : phy=="802.11ac" ? "Wi-Fi 5" : phy=="802.11n" ? "Wi-Fi 4" : phy=="802.11be" ? "Wi-Fi 7" : "");
                print "The SSID is: " val(ssid);
                print "The BSSID is: " val(bssid);
                print "The protocol is: " val(phy) (gen!="" ? " ( " gen " )" : "");
                print "The Authentication is: " val(security);
                print "The Channel is: " val(channel);
                print "The Signal is: " val(signal);
                print "The Noise is: " val(noise);
                if (signal ~ /^-?[0-9]+([.][0-9]+)?[ ]*dBm$/ && noise ~ /^-?[0-9]+([.][0-9]+)?[ ]*dBm$/) {
                    printf "The SNR is: %g dB\n", (signal+0)-(noise+0);
                } else {
                    print "The SNR is: Unavailable";
                }
                print "The Transmit Rate is: " val(rate) (rate!="" ? " Mbps" : "");
            }' "$work_dir/wifi"
    elif [ "$connection_type" = Ethernet ]; then
        media=$(sed -n 's/^[[:space:]]*media: //p' "$work_dir/interface")
        speed=$(printf '%s\n' "$media" | sed -nE 's/.*[^0-9]([0-9]+)base.*/\1/p')
        duplex=Unavailable
        case "$media" in *full-duplex*) duplex='Full duplex';; *half-duplex*) duplex='Half duplex';; esac
        printf 'The Duplex Mode is: %s\n' "$duplex"
        if [ -n "$speed" ]; then
            printf 'The Link Speed is: %s Mbps\n' "$speed"
        else
            printf 'The Link Speed is: Unavailable\n'
        fi
    fi

############################################## COLLECTING INFORMATION ##############################################

    section 'Collecting Information...'
    printf 'The default interface is %s (%s)\n' "${hardware_port:-Network}" "${iface:-Unavailable}"
    printf 'Interface %s is %s, %s, %s%s, Gateway %s\n' "${iface:-Unavailable}" "$(if [ "$state" = Connected ]; then echo UP; elif [ "$state" = Disconnected ]; then echo DOWN; else echo Unknown; fi)" "$method" "${ip:-Unavailable}" "${prefix:+/$prefix}" "${gateway:-Unavailable}"
    ipv6=$(awk '$1=="inet6"{printf "%s%s",sep,$2;sep=", "}' "$work_dir/interface")
    [ -z "$ipv6" ] || printf 'The IPv6 Addresses are: %s\n' "$ipv6"
    scutil --dns > "$work_dir/dns" 2>/dev/null
    dns=$(awk '/nameserver\[[0-9]+\]/{print $3}' "$work_dir/dns" | sort -u)
    printf 'The DNS Servers are: %s\n' "$(printf '%s\n' "$dns" | paste -sd ',' -)"
    # Preserve split-DNS domains without printing mDNS machinery or duplicate blocks.
    awk '/^resolver #/{domain="";server=""} /domain[ ]*:/{domain=$3} /nameserver\[/{server=server " " $3} /^$/{if(domain!="" && server!="") print "DNS Domain: " domain " | Servers:" server;domain="";server=""} END{if(domain!="" && server!="") print "DNS Domain: " domain " | Servers:" server}' "$work_dir/dns" | sort -u
    public_ip=$(dig +time=3 +tries=1 +short myip.opendns.com @208.67.222.220 A 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/{print;exit}')
    printf 'The Public IP Address is: %s\n' "${public_ip:-Unavailable}"

################################################## STARTING TESTS ##################################################

    section 'Starting Tests...'
    traceroute -n -m 3 -w 1 8.8.8.8 > "$work_dir/trace" 2>&1
    awk '$1 ~ /^[0-9]+$/ {ip="0.0.0.0";for(i=2;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){ip=$i;break} print $1,ip}' "$work_dir/trace" > "$work_dir/hops"
    while read -r number hop; do
        if [ "$hop" = 0.0.0.0 ]; then
            # Requested Windows-compatible placeholder; never ping 0.0.0.0.
            printf 'Ping test to hop #%s 0.0.0.0 response time Min/Avg/Max = /0/ ms, Packet Loss 100%%\n' "$number"
        else
            ping_test "hop #$number" "$hop"
        fi
    done < "$work_dir/hops"
    [ -s "$work_dir/hops" ] || printf 'Traceroute could not identify hops.\n'
    for server in $dns; do ping_test 'Host DNS server' "$server"; done
    ping_test 'Public DNS server' 8.8.8.8

############################################ LOCAL DOMAIN JOINED STATUS ############################################

    if dsconfigad -show > "$work_dir/domain" 2>/dev/null; then
        server=$(awk -F '= ' '/Active Directory Domain/{print $2;exit}' "$work_dir/domain")
        if [ -n "$server" ]; then ping_test 'Domain Controller' "$server"
        else printf 'The system is not joined to a domain\n'; fi
    else
        printf 'Active Directory status unavailable\n'
    fi

############################################### DNS RESOLUTION TEST ################################################

    for server in $dns; do
        dig +time=3 +tries=1 @"$server" cisco.com A > "$work_dir/dig" 2>&1
        awk -v server="$server" '
            /status:/ {s=$0;sub(/^.*status: /,"",s);sub(/,.*/,"",s)}
            $4=="A" && $1!~/^;/ {ips=ips (ips!="" ? ", " : "") $5}
            END {if(s=="NOERROR" && ips!="") printf "DNS Resolver test for %s, cisco.com %s - OK\n",server,ips;
                 else printf "DNS Resolver test for %s, cisco.com - FAILED (%s)\n",server,(s!="" ? s : "no response");}' "$work_dir/dig"
    done

################################### PORT TEST TO PUBLIC SITES ON PORT 80 AND 443 ###################################

    for port in 80 443; do
        if nc -z -G 5 -w 5 cisco.com "$port" >/dev/null 2>&1; then
            printf 'Port Connectivity test for cisco.com on port %s - OK\n' "$port"
        else
            printf 'Port Connectivity test for cisco.com on port %s FAILED\n' "$port"
        fi
    done

################################################ RUNNING SPEED TEST ################################################

    run_speedtest

####################################### NETWORK CONNECTIVITY TESTS COMPLETED #######################################

    section 'Network Connectivity Tests Completed...'


######################################### COLLECTING WIFI / ETHERNET LOGS ##########################################

    printf 'Logs: solo eventos accesibles al usuario; los campos privados pueden estar ocultos.\n'
    if [ "$connection_type" = WiFi ]; then
        collect_logs WiFi '(process == "airportd" OR subsystem BEGINSWITH "com.apple.wifi")'
    elif [ "$connection_type" = Ethernet ]; then
        # Query only messages explicitly identifying Ethernet/the current device.
        if [[ "$iface" =~ ^en[0-9]+$ ]]; then
            collect_logs Ethernet "(process == \"configd\" OR process == \"kernel\" OR process == \"eapolclient\") AND (eventMessage CONTAINS[c] \"$iface\")"
            printf 'Los eventos que no identifican la interfaz se omiten; cobertura distinta a Windows.\n'
        fi
    else
        printf 'No se atribuyen logs WiFi/Ethernet a una interfaz virtual o no identificada.\n'
    fi
}


################################################## SAVING OUTPUT ###################################################

# Synchronous pipeline: tee finishes before curl reads the report.
# Both stdout and stderr are captured. No upload configuration is printed.
diagnose 2>&1 | tee "$report"
pipeline_status=("${PIPESTATUS[@]}")
if [ "${pipeline_status[1]}" -ne 0 ] || [ ! -s "$report" ]; then
    printf '\nNo fue posible capturar el reporte de texto.\n' >&2
    exit 1
fi

############################################### SENDING TEXT REPORT ################################################

http_code=$(curl -sS --connect-timeout 15 --max-time 120 \
    -H 'Authorization: Basic '"$(printf '%s' 'FlexvityTS:8QoGq$tTrte6cQ$i' | base64)" \
    -H 'Content-Type: text/plain; charset=utf-8' \
    -H "X-PC-Name: $pc_name" -H "X-File-Name: $report_name" \
    --data-binary "@$report" -o "$work_dir/response.json" -w '%{http_code}' \
    "$upload_uri" 2> "$work_dir/upload-error")
curl_status=$?
uploaded_name=''
if [ "$curl_status" -eq 0 ] && [[ "$http_code" == 2[0-9][0-9] ]]; then
    uploaded_name=$(osascript -l JavaScript -e 'ObjC.import("Foundation"); function run(a){var s=$.NSString.stringWithContentsOfFileEncodingError(a[0],$.NSUTF8StringEncoding,null); var j=JSON.parse(ObjC.unwrap(s)); return typeof j.archivo === "string" ? j.archivo : "";}' "$work_dir/response.json" 2>/dev/null)
fi

################################################## FINAL MESSAGE ###################################################

if [ "$uploaded_name" = "$report_name" ]; then
    printf '\nEl reporte de texto fue enviado correctamente.\n'
    printf '\nPor favor, envie este codigo al Departamento de Soporte: %s\n\n' "$report_name"
else
    printf '\nNo fue posible confirmar el envio del reporte de texto.\n'
    printf 'Codigo local del reporte (envio no confirmado): %s\n' "$report_name"
    exit 1
fi


####################################################### END ########################################################
