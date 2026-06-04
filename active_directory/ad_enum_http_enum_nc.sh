#!/bin/bash

# AD Scan Script with OPSEC-friendly HTML Report (no credentials shown)
# Kali Linux - Active Directory enumeration and basic vuln checks

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

# Start HTML - NO credentials shown
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
    <p><strong>Domain (if provided):</strong> ${DOMAIN:-Not specified}</p>
    <hr>
EOF

add_section() {
    local title="$1"
    local class="$2"
    local content="$3"
    # Escape HTML special characters
    content=$(echo "$content" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    printf "<div class=\"section $class\">\n<h2>%s</h2>\n<pre>%s</pre>\n</div>\n" "$title" "$content" >> "$REPORT"
}

echo "[*] Running Nmap scan for AD ports..."
nmap_output=$(nmap -p 88,135,389,445,636 --open -oN - $TARGET 2>&1)
add_section "Nmap Scan - AD Related Ports (88,135,389,445,636)" "info" "$nmap_output"

# Extract potential DCs
echo "$nmap_output" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $5}' | sort -u > potential_dcs.txt

# Fallback for single IP target
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

# Process each DC
for IP in $(cat potential_dcs.txt 2>/dev/null); do
    [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue

    echo "[*] Enumerating $IP"

    # Null session check
    cme_output=$(crackmapexec smb "$IP" 2>&1 || echo "Error running CME")
    add_section "CrackMapExec - SMB Null Session ($IP)" "info" "$cme_output"

    # Authenticated enumeration (if credentials were provided)
    if [ -n "$USER" ] && [ -n "$PASS" ]; then
        # Use domain\user format if domain provided, otherwise just user
        if [ -n "$DOMAIN" ]; then
            auth_user="$DOMAIN\\$USER"
        else
            auth_user="$USER"
        fi

        cme_auth=$(crackmapexec smb "$IP" -u "$auth_user" -p "$PASS" --shares --users --groups --pass-pol 2>&1)
        add_section "CrackMapExec - Authenticated Enumeration ($IP)" "info" "$cme_auth"
    fi

    # Enum4linux-ng (null session)
    enum_output=$(enum4linux-ng -A "$IP" 2>&1 || echo "Error running enum4linux-ng")
    add_section "Enum4linux-ng - Full Enumeration ($IP)" "info" "$enum_output"

    # ZeroLogon
    zl_output=$(netexec smb "$IP" -u '' -p '' -M zerologon 2>&1)
    if echo "$zl_output" | grep -qi "VULNERABLE"; then
        add_section "ZeroLogon (CVE-2020-1472) - $IP" "vuln" "$zl_output"
    else
        add_section "ZeroLogon Check - $IP" "success" "$zl_output"
    fi

    # PetitPotam (or newer coerce)
    pp_output=$(netexec smb "$IP" -M petitpotam 2>&1 || echo "")
    if [[ -z "$pp_output" || "$pp_output" == *"REMOVED"* ]]; then
        pp_output=$(netexec smb "$IP" -M coerce_plus 2>&1 || echo "Coerce check not available")
    fi
    add_section "Coerce Authentication Check (PetitPotam/Coerce+) - $IP" "info" "$pp_output"

    # NoPac (only if creds)
    if [ -n "$USER" ] && [ -n "$PASS" ]; then
        nopac_output=$(netexec smb "$IP" -u "$auth_user" -p "$PASS" -M nopac 2>&1)
        add_section "NoPac Check - $IP" "info" "$nopac_output"
    fi
done

# Domain-wide LDAP checker (if domain + creds)
if [ -n "$DOMAIN" ] && [ -n "$USER" ] && [ -n "$PASS" ] && [ -s potential_dcs.txt ]; then
    kdc=$(head -1 potential_dcs.txt)
    auth_user="${DOMAIN}\\${USER}"
    ldap_output=$(netexec ldap "$DOMAIN" -u "$auth_user" -p "$PASS" --kdcHost "$kdc" -M ldap-checker 2>&1)
    add_section "LDAP Checker (Domain-wide)" "info" "$ldap_output"
fi

# Finalize report
cat << EOF >> "$REPORT"
    <div class="section">
        <h2>Scan Complete</h2>
        <p>Report generated on $(date). Review red-bordered sections for critical findings.</p>
    </div>
</body>
</html>
EOF

echo "[+] Scan complete! Report generated: $REPORT"
echo "    Open with: firefox $REPORT &"

# Cleanup
rm -f potential_dcs.txt
