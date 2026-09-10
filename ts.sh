#!/bin/bash

######################################################################
#  Date: 09 Sep 2026 11:08:30 -05:00 (America/Bogota)                #
#  Name: Network Troubleshooting Script                              #
#  Task: To verify the network connectivity performance and errors   #
#  By: Daniel Benavides                                              #
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
    local label="$1" target="$2"
    [ -n "$target" ] || return 0
    printf '\nPing test to %s (%s):\n' "$label" "$target"
    /sbin/ping -n -c 8 -W 1000 "$target"
}


##################################### WIFI / ETHERNET LOG COLLECTION FUNCTION ######################################

collect_logs() {
    local label="$1" predicate="$2"
    # --style ndjson permits distinguishing actual events from log headers.
    # Do not claim that all system networking messages belong to one adapter.
    if /usr/bin/log show --last 24h --style ndjson --info --predicate "$predicate" \
        > "$work_dir/events" 2> "$work_dir/log-errors"; then
        if grep -q '"eventMessage"' "$work_dir/events"; then
            section "$label Events - Last 24 Hours (macOS unified log)"
            cat "$work_dir/events"
        else
            printf '\nNo hubo logs de %s en las ultimas 24 horas.\n' "$label"
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
    local route_info iface gateway hardware_port connection_type dns server port hops hop
    section 'Starting Network Connectivity Test...'

################################################ SYSTEM INFORMATION ################################################

    section 'System Information...'
    printf 'The Date and Time is: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
    printf 'The Computer Name is: %s\n' "$pc_name"
    printf 'The Manufacturer is: Apple\n'
    printf 'The Model is: %s\n' "$(sysctl -n hw.model)"
    printf 'The Architecture is: %s\n' "$(uname -m)"
    printf 'The Serial Number is: %s\n' "$(ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/{print $(NF-1)}')"
    sw_vers


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


########################################### WIFI / ETHERNET INFORMATION ############################################

    section "$connection_type Information..."
    printf 'The default interface is: %s\n' "${iface:-Unavailable}"
    printf 'The Hardware Port is: %s\n' "${hardware_port:-Unavailable (possibly VPN or virtual interface)}"
    printf 'The Gateway is: %s\n' "${gateway:-Unavailable}"
    if [ -n "$iface" ]; then
        ifconfig "$iface"
        printf '\nDHCP information (if available):\n'
        ipconfig getpacket "$iface" 2>/dev/null || printf 'No disponible; puede utilizar una configuracion estatica o una interfaz virtual.\n'
    fi
    if [ "$connection_type" = WiFi ]; then
        printf '\nWiFi information supplied by macOS:\n'
        system_profiler SPAirPortDataType -detailLevel basic -timeout 30 || printf 'No fue posible obtener los detalles WiFi.\n'
        printf '\nSSID/BSSID y otros datos pueden estar ocultos por macOS.\n'
        printf 'No hay equivalencia garantizada para tasas RX/TX y fecha del driver de Windows.\n'
    elif [ "$connection_type" = Ethernet ]; then
        printf 'El campo media de ifconfig muestra velocidad/duplex cuando el adaptador los expone.\n'
        printf 'Fecha y proveedor del driver: no disponibles en el mismo formato que Windows.\n'
    fi


############################################## COLLECTING INFORMATION ##############################################

    section 'Collecting Information...'
    scutil --dns
    dns=$(scutil --dns | awk '/nameserver\[[0-9]+\]/{print $3}' | sort -u)
    printf '\nThe Public IP Address is: '
    dig +time=3 +tries=1 +short myip.opendns.com @208.67.222.220 A


################################################## STARTING TESTS ##################################################

    section 'Starting Tests...'

############################################### TRACEROUTE PING TEST ###############################################

    printf 'Traceroute (first 3 hops):\n'
    traceroute -n -m 3 -w 1 8.8.8.8 > "$work_dir/trace" 2>&1
    cat "$work_dir/trace"
    hops=$(awk '$1 ~ /^[0-9]+$/ {for(i=2;i<=NF;i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i}' "$work_dir/trace" | sort -u)
    for hop in $hops; do ping_test 'route hop' "$hop"; done
    if [[ "$gateway" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then ping_test 'gateway' "$gateway"; fi

###################################### DNS CONNECTIVITY AND RESOLUTION TESTS #######################################

    for server in $dns; do
        case "$server" in
            *:*) printf '\nIPv6 DNS ping (%s):\n' "$server"; ping6 -n -c 8 "$server" ;;
            *) ping_test 'Host DNS server' "$server" ;;
        esac
    done

################################################ PUBLIC DNS STATUS #################################################

    ping_test 'Public DNS server' 8.8.8.8

############################################ LOCAL DOMAIN JOINED STATUS ############################################

    printf '\nActive Directory configuration:\n'
    if ! dsconfigad -show > "$work_dir/domain" 2>/dev/null || [ ! -s "$work_dir/domain" ]; then
        printf 'No se pudo confirmar una union a Active Directory.\n'
    else
        cat "$work_dir/domain"
        server=$(awk -F '= ' '/Active Directory Domain/{print $2; exit}' "$work_dir/domain")
        ping_test 'Active Directory domain' "$server"
    fi

###################################### DNS CONNECTIVITY AND RESOLUTION TESTS #######################################

    for server in $dns; do
        printf '\nDNS Resolver test for %s, cisco.com:\n' "$server"
        dig +time=3 +tries=1 @"$server" cisco.com A
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
    --user 'flexvity:flexvity' \
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
    printf '\nPor favor, envie este codigo al Departamento de Soporte: %s\n' "$report_name"
else
    printf '\nNo fue posible confirmar el envio del reporte de texto.\n'
    printf 'Codigo local del reporte (envio no confirmado): %s\n' "$report_name"
    exit 1
fi


####################################################### END ########################################################
