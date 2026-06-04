#!/bin/bash

# AD Scan Script - Reliable authenticated enumeration (no double-domain bug)

TARGET=$1
DOMAIN=$2          # e.g., bctec.local
USER=$3            # Just the username, e.g., administrator (NO domain prefix)
PASS=$4

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip> [domain] <username> <password>"
    echo "Example: $0 10.10.100.18 bctec.local administrator Propose-Headache6-Outdated"
    exit 1
fi

REPORT="ad_scan_report_$(date +%Y%m%d_%H%M%S).html"
echo "[*] Generating report: $REPORT"

# HTML start (OPSEC-safe)
cat << EOF > "$REPORT"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AD Scan Report - $(date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; color: #333; }
        h1, h2 { color: #2c3e50; }
        pre { background: #eee; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; }
        .section { margin-bottom: 40px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .vuln { border-left: 5px solid #e74c3c; }
        .info { border-left: 5px solid #3498db; }
        .success { border-left: 5px solid #2ecc71; }
        .warning { border-left: 5px solid #f39c12; }
    </style>
</head>
<body>
    <h1>Active Directory Scan Report</h1>
    <p><strong>Target:</strong> $TARGET</p>
    <p><strong>Date:</strong> $(date)</p>
    <p><strong>Domain (if provided):</strong> ${DOMAIN:-Not specified}</p>
    <hr>
EOF

add_section() {
    local title="$1"
    local class="$2"
    local content="$3"
    content=$(echo "$content" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    printf "<div class=\"section $class\">\n<h2>%s</h2>\n<pre>%s</pre>\n</div>\n" "$title" "$content" >> "$REPORT"
}

# Nmap + DC detection
nmap_output=$(nmap -p 88,135,389,445,636 --open -oN - $TARGET 2>&1)
add_section "Nmap AD Ports Scan" "info" "$nmap_output"

echo "$nmap_output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > potential_dcs.txt
[ ! -s potential_dcs.txt ] && [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "$TARGET" >> potential_dcs.txt

if [ ! -s potential_dcs.txt ]; then
    add_section "No DCs Found" "warning" "No open AD ports detected."
else
    add_section "Potential Domain Controllers" "success" "$(cat potential_dcs.txt)"
fi

for IP in $(cat potential_dcs.txt); do
    echo "[*] Processing $IP"

    # Null session
    null_output=$(crackmapexec smb "$IP" 2>&1)
    add_section "CrackMapExec Null Session ($IP)" "info" "$null_output"

    # Authenticated - ONLY use plain username (no domain prefix!)
    if [ -n "$USER" ] && [ -n "$PASS" ]; then
        auth_output=$(crackmapexec smb "$IP" -u "$USER" -p "$PASS" --shares --users --groups --pass-pol 2>&1)
        add_section "CrackMapExec Authenticated Enumeration ($IP)" "info" "$auth_output"
    fi

    # Enum4linux-ng
    enum_output=$(enum4linux-ng -A "$IP" 2>&1)
    add_section "Enum4linux-ng ($IP)" "info" "$enum_output"

    # ZeroLogon
    zl_output=$(netexec smb "$IP" -u '' -p '' -M zerologon 2>&1)
    if echo "$zl_output" | grep -qi "VULNERABLE"; then
        add_section "ZeroLogon ($IP)" "vuln" "$zl_output"
    else
        add_section "ZeroLogon Check ($IP)" "success" "$zl_output"
    fi

    # Coerce check
    coerce_output=$(netexec smb "$IP" -M coerce_plus 2>&1 || netexec smb "$IP" -M petitpotam 2>&1)
    add_section "Coerce Check ($IP)" "info" "$coerce_output"

    # NoPac (if creds)
    if [ -n "$USER" ] && [ -n "$PASS" ]; then
        nopac_output=$(netexec smb "$IP" -u "$USER" -p "$PASS" -M nopac 2>&1)
        add_section "NoPac Check ($IP)" "info" "$nopac_output"
    fi
done

# Domain-wide LDAP (if domain + creds)
if [ -n "$DOMAIN" ] && [ -n "$USER" ] && [ -n "$PASS" ] && [ -s potential_dcs.txt ]; then
    kdc=$(head -1 potential_dcs.txt)
    ldap_output=$(netexec ldap "$DOMAIN" -u "$USER" -p "$PASS" --kdcHost "$kdc" -M ldap-checker 2>&1)
    add_section "Domain-wide LDAP Checker" "info" "$ldap_output"
fi

# Finish report
cat << EOF >> "$REPORT"
    <div class="section">
        <h2>Scan Complete</h2>
        <p>Report generated on $(date).</p>
    </div>
</body>
</html>
EOF

echo "[+] Report ready: $REPORT"
echo "    View with: firefox $REPORT &"
rm -f potential_dcs.txt
