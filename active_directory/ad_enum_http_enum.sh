#!/bin/bash

# AD Scan Script with HTML Report Export for Kali Linux
# Scans for Active Directory environments and checks for common vulnerabilities
# Outputs everything to both terminal and a styled HTML report

# WARNING: For authorized penetration testing only!

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

# Start HTML report
cat << EOF > "$REPORT"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Active Directory Scan Report - $(date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; color: #333; }
        h1, h2 { color: #2c3e50; }
        pre { background: #eee; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .section { margin-bottom: 40px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .vuln { border-left: 5px solid #e74c3c; }
        .info { border-left: 5px solid #3498db; }
        .success { border-left: 5px solid #2ecc71; }
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

# Function to append section to HTML report
add_section() {
    local title="$1"
    local class="$2"
    local content="$3"
    printf "<div class=\"section $class\">\n<h2>%s</h2>\n<pre>%s</pre>\n</div>\n" "$title" "$content" >> "$REPORT"
}

echo "[*] Starting AD discovery scan on $TARGET"

# Step 1: Nmap scan for AD ports
echo "[*] Running Nmap scan..."
nmap_output=$(nmap -p 88,135,389,445,636 --open -oN - $TARGET)
add_section "Nmap Scan - AD Related Ports (88,135,389,445,636)" "info" "$nmap_output"

# Extract potential DCs
grep "open" <(echo "$nmap_output") | awk '{print $2}' | sort -u > potential_dcs.txt

if [ ! -s potential_dcs.txt ]; then
    add_section "No Potential Domain Controllers Found" "vuln" "No hosts with common AD ports open were detected."
    cat << EOF >> "$REPORT"
</body>
</html>
EOF
    echo "[!] No potential DCs found. Report generated: $REPORT"
    exit 0
fi

add_section "Potential Domain Controllers Detected" "success" "$(cat potential_dcs.txt | tr '\n' '<br>')"

# Step 2: Enumerate each potential DC
for IP in $(cat potential_dcs.txt); do
    echo "[*] Enumerating $IP"

    # CrackMapExec basic (null session)
    cme_output=$(crackmapexec smb $IP 2>&1)
    add_section "CrackMapExec - SMB ($IP)" "info" "$cme_output"

    # If credentials provided
    if [ -n "$USER" ] && [ -n "$PASS" ]; then
        cme_auth_output=$(crackmapexec smb $IP -u "$USER" -p "$PASS" --shares --users --groups --pass-pol 2>&1)
        add_section "CrackMapExec - Authenticated Enum ($IP)" "info" "$cme_auth_output"
    fi

    # Enum4linux-ng
    enum_output=$(enum4linux-ng -A $IP 2>&1)
    add_section "Enum4linux-ng - Full Enumeration ($IP)" "info" "$enum_output"

    # Vulnerability checks
    echo "[*] Checking vulnerabilities on $IP"

    # ZeroLogon
    zerologon_output=$(netexec smb $IP -u '' -p '' -M zerologon 2>&1)
    if echo "$zerologon_output" | grep -qi "VULNERABLE"; then
        add_section "ZeroLogon (CVE-2020-1472) - $IP" "vuln" "$zerologon_output"
    else
        add_section "ZeroLogon Check - $IP" "success" "$zerologon_output"
    fi

    # PetitPotam
    petitpotam_output=$(netexec smb $IP -M petitpotam 2>&1)
    add_section "PetitPotam Coerce Check - $IP" "info" "$petitpotam_output"

    # NoPac (if creds)
    if [ -n "$USER" ] && [ -n "$PASS" ]; then
        nopac_output=$(netexec smb $IP -u "$USER" -p "$PASS" -M nopac 2>&1)
        add_section "NoPac (CVE-2021-42278/42287) Check - $IP" "info" "$nopac_output"
    fi
done

# Optional domain-wide checks
if [ -n "$DOMAIN" ] && [ -n "$USER" ] && [ -n "$PASS" ] && [ -s potential_dcs.txt ]; then
    kdc=$(head -1 potential_dcs.txt)
    ldap_checker=$(netexec ldap $DOMAIN -u "$USER" -p "$PASS" --kdcHost $kdc -M ldap-checker 2>&1)
    add_section "LDAP Checker (Domain-wide)" "info" "$ldap_checker"
fi

# Finalize HTML
cat << EOF >> "$REPORT"
    <div class="section">
        <h2>Scan Complete</h2>
        <p>Report generated on $(date). Review sections above, especially those highlighted in red for potential vulnerabilities.</p>
    </div>
</body>
</html>
EOF

echo "[+] Scan complete!"
echo "[+] HTML report generated: $REPORT"
echo "    Open it in your browser: firefox $REPORT &"

# Cleanup temporary files (optional)
rm -f potential_dcs.txt dc_scan.txt
