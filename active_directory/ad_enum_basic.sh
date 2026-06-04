#!/bin/bash

# AD Scan Script for Kali Linux
# This script scans a network for potential Active Directory domain controllers
# and performs basic enumeration and common vulnerability checks using tools available in Kali.
# Tools used: nmap, crackmapexec (cme), enum4linux-ng, zerologon tester (netexec module)
#
# WARNING: This script is for authorized penetration testing and educational purposes only.
# Unauthorized use against networks you do not own or have explicit permission to test is illegal.
# Always obtain written permission before scanning or testing any network.

# Usage: ./ad_scan.sh <target_ip_or_range> [domain] [username] [password]
# Example: ./ad_scan.sh 192.168.1.0/24 example.com user pass
# If no credentials provided, null session/anonymous checks will be attempted where possible.

TARGET=$1
DOMAIN=$2
USER=$3
PASS=$4

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip_or_range> [domain] [username] [password]"
    exit 1
fi

echo "[*] Starting AD discovery scan on $TARGET"

# Step 1: Discover potential Domain Controllers (ports: 389 LDAP, 636 LDAPS, 88 Kerberos, 445 SMB, 135 RPC)
nmap -p 88,135,389,445,636 --open -oG dc_scan.txt $TARGET

# Extract live hosts with AD-related ports open
grep "open" dc_scan.txt | awk '{print $2}' > potential_dcs.txt

echo "[+] Potential Domain Controllers/AD hosts found:"
cat potential_dcs.txt

# Step 2: For each potential DC, perform basic enumeration
for IP in $(cat potential_dcs.txt); do
    echo "[*] Enumerating $IP"

    # Basic SMB info (null session possible)
    crackmapexec smb $IP

    # If credentials provided, more detailed enum
    if [ ! -z "$USER" ] && [ ! -z "$PASS" ]; then
        crackmapexec smb $IP -u "$USER" -p "$PASS" --shares --users --groups --pass-pol
    fi

    # Enum4linux-ng for comprehensive null/anon enumeration
    enum4linux-ng -A $IP

    # Common vuln checks with netexec/cme modules
    # ZeroLogon (CVE-2020-1472) check
    echo "[*] Checking for ZeroLogon vulnerability on $IP"
    netexec smb $IP -u '' -p '' -M zerologon

    # NoPac (if credentials)
    if [ ! -z "$USER" ] && [ ! -z "$PASS" ]; then
        netexec smb $IP -u "$USER" -p "$PASS" -M nopac
    fi

    # PetitPotam (coerce NTLM auth)
    netexec smb $IP -M petitpotam

done

# Optional: If domain and creds provided, broader AD enum
if [ ! -z "$DOMAIN" ] && [ ! -z "$USER" ] && [ ! -z "$PASS" ]; then
    echo "[*] Performing domain-wide enumeration with credentials"
    crackmapexec ldap $DOMAIN -u "$USER" -p "$PASS" --kdcHost $(head -1 potential_dcs.txt) -M ldap-checker
fi

echo "[+] Scan complete. Review outputs for potential vulnerabilities (e.g., null sessions, weak policies, exploitable CVEs)."
