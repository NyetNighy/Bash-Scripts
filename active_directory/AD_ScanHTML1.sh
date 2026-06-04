#!/bin/bash

# Fixed AD Scan Script with HTML Report for Kali Linux

TARGET=$1
DOMAIN=$2
USER=$3
PASS=$4

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip_or_range> [domain] [username] [password]"
    exit 1
fi

REPORT="ad_scan_report_$(date +%Y%m%d_%H%M%S).html"
echo "[*] Report will be saved to $REPORT"

# Start HTML
cat << EOF > "$REPORT"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Active Directory Scan Report - $(date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; color: #333; }
        h1, h2 { color: #2c3e50; }
        pre { background: #eee; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; }
        .section { margin-bottom: 40px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .vuln { border-left: 5px solid #e74c3c; }
        .info { border-left: 5px solid #3498db; }
        .success { border-left: 5px solid #2ecc71; }
        .warning { border-left: 5px solid #f39c12; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Active Directory Penetration Test Scan Report</h1>
    <p><strong>Target:</strong> $TARGET</p>
    <p><strong>Date:</strong> $(date)</p>
    <p><strong>Domain:</strong> ${DOMAIN:-N/A}</p>
    <p><strong>Credentials Used:</strong> ${USER:-Anonymous/null session}</p>
    <hr>
EOF

add_section() {
    local title="$1"
    local class="$2"
    local content="$3"
    # Escape HTML special chars in content
    content=$(echo "$content" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    printf "<div class=\"section $class\">\n<h2>%s</h2>\n<pre>%s</pre>\n</div>\n" "$title" "$content" >> "$REPORT"
}

echo "[*] Running Nmap scan for AD ports..."
nmap_output=$(nmap -p 88,135,389,445,636 --open -oN - $TARGET 2>&1)
add_section "Nmap Scan - AD Related Ports (88,135,389,445,636)" "info" "$nmap_output"

# Extract live hosts with open ports
echo "$nmap_output" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $5}' | sort -u > potential_dcs.txt

# If nothing extracted (e.g., single host format), fallback to target if it's an IP
if [ ! -s potential_dcs.txt ]; then
    if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$TARGET" > potential_dcs.txt
    fi
fi

if [ ! -s potential_dcs.txt ]; then
    add_section "No Potential Domain Controllers Found" "warning" "No hosts with AD-related ports open were detected."
else
    add_section "Potential Domain Controllers Detected" "success" "$(cat potential_dcs.txt)"
fi

cat << EOF >> "$REPORT"

EOF

# Enumerate each valid IP
for IP in $(cat potential_dcs.txt 2>/dev/null); do
    # Basic validity check
    if ! [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        continue
    fi

    echo "[*] Enumerating $IP"

    # CrackMapExec basic (null session)
    cme_output=$(crackmapexec smb "$IP" 2>&1 || echo "Error running CME")
    add_section "CrackMapExec - SMB Null Session ($IP)" "info" "$cme_output"

    # Authenticated if creds provided
    if [ -n "$USER" ] && [ -n "$PASS" ]; then
        cme_auth=$(crackmapexec smb "$IP" -u "$USER" -p "$PASS" --shares --users --groups --pass-pol 2>&1)
        add_section "CrackMapExec - Authenticated Enumeration ($IP)" "info" "$cme_auth"
    fi

    # Enum4linux-ng
    enum_output=$(enum4linux-ng -A "$IP" 2>&1 || echo "Error running enum4linux-ng")
    add_section "Enum4linux-ng - Full Enumeration ($IP)" "info" "$enum_output"

    # ZeroLogon
    zl_output=$(netexec smb "$IP" -u '' -p '' -M zerologon 2>&1)
    if echo "$zl_output" | grep -qi "VULNERABLE"; then
        add_section "ZeroLogon (CVE-2020-1472) - $IP" "vuln" "$zl_output"
    else
        add_section "ZeroLogon Check - $IP" "success" "$zl_output"
    fi

    # PetitPotam
    pp_output=$(netexec smb "$IP" -M petitpotam 2>&1)
    add_section "PetitPotam Coerce Check - $IP" "info" "$pp_output"

    # NoPac (if creds)
    if [ -n "$USER" ] && [ -n "$PASS" ]; then
        nopac_output=$(netexec smb "$IP" -u "$USER" -p "$PASS" -M nopac 2>&1)
        add_section "NoPac Check - $IP" "info" "$nopac_output"
    fi
done

# Domain-wide if possible
if [ -n "$DOMAIN" ] && [ -n "$USER" ] && [ -n "$PASS" ] && [ -s potential_dcs.txt ]; then
    kdc=$(head -1 potential_dcs.txt)
    ldap_output=$(netexec ldap "$DOMAIN" -u "$USER" -p "$PASS" --kdcHost "$kdc" -M ldap-checker 2>&1)
    add_section "LDAP Checker (Domain-wide)" "info" "$ldap_output"
fi

# Finalize
cat << EOF >> "$REPORT"
    <div class="section">
        <h2>Scan Complete</h2>
        <p>Report generated on $(date). Check red-bordered sections for vulnerabilities.</p>
    </div>
</body>
</html>
EOF

echo "[+] Scan complete! Report: $REPORT"
echo "    Open with: firefox $REPORT &"

# Cleanup
rm -f potential_dcs.txt
