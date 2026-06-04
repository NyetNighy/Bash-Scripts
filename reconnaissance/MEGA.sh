#!/bin/bash

# Modular Comprehensive Pentest Script for Kali Linux
# Includes: DNS, Nmap, Nikto, Gobuster, SMB, SNMP, Nuclei, Metasploit
# Usage: ./modular_pentest.sh <target> [options]
# Target can be IP or domain (e.g., example.com or 192.168.1.100)

set -euo pipefail

# Default settings
TARGET=""
RUN_NMAP=true
RUN_NIKTO=true
RUN_GOBUSTER=true
RUN_SMB=true
RUN_DNS=true
RUN_SNMP=true
RUN_MSF=false          # Disabled by default (can be slow/noisy)
RUN_NUCLEI=false       # Disabled by default (can be noisy)
NUCLEI_AGGRESSIVE=false
MSF_AGGRESSIVE=false
WORDLIST="/usr/share/wordlists/dirb/common.txt"
DNS_WORDLIST="/usr/share/wordlists/dnsrecon/namelist.txt"
SNMP_WORDLIST="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt"
THREADS=50
DATE=$(date +%Y-%m-%d_%H-%M)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+] $1${NC}"; }
warn()  { echo -e "${YELLOW}[-] $1${NC}"; }
error() { echo -e "${RED}[!] $1${NC}"; }

usage() {
    grep "^#" "$0" | cut -c 4-
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        --no-nmap) RUN_NMAP=false ;;
        --no-nikto) RUN_NIKTO=false ;;
        --no-gobuster) RUN_GOBUSTER=false ;;
        --no-smb) RUN_SMB=false ;;
        --no-dns) RUN_DNS=false ;;
        --no-snmp) RUN_SNMP=false ;;
        --no-msf) RUN_MSF=false ;;
        --no-nuclei) RUN_NUCLEI=false ;;
        --msf) RUN_MSF=true ;;
        --msf-aggressive) RUN_MSF=true; MSF_AGGRESSIVE=true ;;
        --nuclei) RUN_NUCLEI=true ;;
        --nuclei-aggressive) RUN_NUCLEI=true; NUCLEI_AGGRESSIVE=true ;;
        --wordlist) WORDLIST="$2"; shift ;;
        --dns-wordlist) DNS_WORDLIST="$2"; shift ;;
        --snmp-wordlist) SNMP_WORDLIST="$2"; shift ;;
        --threads) THREADS="$2"; shift ;;
        --all) RUN_NMAP=true; RUN_NIKTO=true; RUN_GOBUSTER=true; RUN_SMB=true; RUN_DNS=true; RUN_SNMP=true; RUN_MSF=true; RUN_NUCLEI=true ;;
        -*|--*) error "Unknown option: $1"; usage ;;
        *) TARGET="$1" ;;
    esac
    shift
done

if [[ -z "$TARGET" ]]; then
    error "No target specified."
    usage
fi

RESULTS_DIR="pentest_${TARGET}_${DATE}"
mkdir -p "$RESULTS_DIR"
log "Results directory: $RESULTS_DIR"

# ==================== HELPER FUNCTIONS ====================

is_domain() {
    [[ "$TARGET" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && ! [[ "$TARGET" =~ / ]]
}

# ==================== MODULE FUNCTIONS ====================

run_dns_enum() {
    log "Starting DNS enumeration on $TARGET..."

    log "Running dnsrecon..."
    dnsrecon -d "$TARGET" -t std --lifetime 10 -v \
        > "$RESULTS_DIR/dnsrecon_full.txt" 2>/dev/null || warn "dnsrecon failed"

    if [[ -f "$DNS_WORDLIST" ]]; then
        log "Running dnsrecon subdomain brute-force..."
        dnsrecon -d "$TARGET" -D "$DNS_WORDLIST" -t brt \
            > "$RESULTS_DIR/dnsrecon_bruteforce.txt" 2>/dev/null || warn "dnsrecon brute-force failed"
    else
        warn "DNS wordlist not found: $DNS_WORDLIST"
    fi

    log "Running fierce..."
    fierce --domain "$TARGET" --subdomains "$DNS_WORDLIST" --threads 20 \
        > "$RESULTS_DIR/fierce.txt" 2>/dev/null || warn "fierce failed"

    log "DNS enumeration complete."
}

run_nmap() {
    log "Running Nmap aggressive scan on $TARGET..."
    nmap -A -T4 -p- \
        -oN "$RESULTS_DIR/nmap_full.txt" \
        -oX "$RESULTS_DIR/nmap_full.xml" \
        "$TARGET" || warn "Nmap failed or was interrupted."
    
    grep "^[0-9]" "$RESULTS_DIR/nmap_full.txt" | cut -d'/' -f1 > "$RESULTS_DIR/open_ports.txt" 2>/dev/null || touch "$RESULTS_DIR/open_ports.txt"
}

run_nikto() {
    local url=$1
    local port=$2
    log "Running Nikto on $url..."
    nikto -h "$url" -o "$RESULTS_DIR/nikto_port${port}.txt" || warn "Nikto failed on port $port"
}

run_gobuster() {
    local url=$1
    local port=$2
    log "Running Gobuster on $url (wordlist: $WORDLIST, threads: $THREADS)..."
    gobuster dir -u "$url" \
        -w "$WORDLIST" \
        -o "$RESULTS_DIR/gobuster_port${port}.txt" \
        -q -t "$THREADS" --timeout 10s || warn "Gobuster failed on port $port"
}

scan_web_services() {
    local ports=$(grep -E "(80|443|8080|8000|8443|3000|5000|9000)/open" "$RESULTS_DIR/nmap_full.txt" | cut -d'/' -f1 || echo "")

    if [[ -z "$ports" ]]; then
        warn "No common web ports found. Skipping web scans."
        return
    fi

    for port in $ports; do
        proto="http"
        [[ $port -eq 443 || $port -eq 8443 ]] && proto="https"
        url="${proto}://$TARGET:$port"

        [[ $RUN_NIKTO == true ]] && run_nikto "$url" "$port"
        [[ $RUN_GOBUSTER == true ]] && run_gobuster "$url" "$port"
    done
}

scan_smb() {
    local smb_ports=$(grep -E "(139|445)/open" "$RESULTS_DIR/nmap_full.txt" || echo "")

    if [[ -z "$smb_ports" ]]; then
        warn "No SMB ports (139/445) found."
        return
    fi

    log "SMB ports open - Running enum4linux..."
    enum4linux -a "$TARGET" > "$RESULTS_DIR/enum4linux.txt" 2>/dev/null || warn "enum4linux failed"
}

scan_snmp() {
    local snmp_port=$(grep "161/open" "$RESULTS_DIR/nmap_full.txt" || echo "")

    if [[ -z "$snmp_port" ]]; then
        warn "No SNMP port (161/udp) found."
        return
    fi

    log "SNMP port 161/udp open - Starting enumeration..."

    if [[ -f "$SNMP_WORDLIST" ]]; then
        log "Brute-forcing community strings with onesixtyone..."
        onesixtyone -c "$SNMP_WORDLIST" -w 50 -t 5 "$TARGET" > "$RESULTS_DIR/onesixtyone.txt" 2>/dev/null || warn "onesixtyone failed"

        VALID_COMMUNITIES=$(grep -v "Waiting" "$RESULTS_DIR/onesixtyone.txt" | awk '{print $2}' | tr -d '[]' | sort -u)

        if [[ -n "$VALID_COMMUNITIES" ]]; then
            log "Valid community strings found: $VALID_COMMUNITIES"
            echo "$VALID_COMMUNITIES" > "$RESULTS_DIR/snmp_valid_communities.txt"

            COMMUNITY=$(echo "$VALID_COMMUNITIES" | head -n1)
            log "Running snmp-check with community '$COMMUNITY'..."
            snmp-check -c "$COMMUNITY" -w "$TARGET" > "$RESULTS_DIR/snmp-check.txt" 2>/dev/null || warn "snmp-check failed"
        else
            warn "No valid community strings found."
        fi
    else
        warn "SNMP wordlist not found: $SNMP_WORDLIST"
    fi

    log "SNMP enumeration complete."
}

scan_nuclei() {
    if ! command -v nuclei &> /dev/null; then
        warn "Nuclei not found. Install with 'sudo apt install nuclei' and run 'nuclei -update-templates'."
        return
    fi

    local urls_file="$RESULTS_DIR/nuclei_urls.txt"
    local ports=$(grep -E "(80|443|8080|8000|8443|3000|5000|9000)/open" "$RESULTS_DIR/nmap_full.txt" | cut -d'/' -f1 || echo "")

    if [[ -z "$ports" ]]; then
        warn "No web ports found for Nuclei scanning."
        return
    fi

    > "$urls_file"
    for port in $ports; do
        proto="http"
        [[ $port -eq 443 || $port -eq 8443 ]] && proto="https"
        echo "${proto}://$TARGET:$port" >> "$urls_file"
    done

    log "Prepared $(wc -l < "$urls_file") URLs for Nuclei scanning."

    nuclei -update-templates >/dev/null 2>&1 || warn "Failed to update Nuclei templates."

    local tags="misconfiguration,exposed,exposure,default-login,fuzz"
    [[ $NUCLEI_AGGRESSIVE == true ]] && tags="$tags,cve,vuln,vulnerability"

    log "Running Nuclei with tags: $tags ..."
    nuclei -l "$urls_file" \
        -t "$HOME/nuclei-templates" \
        -tags "$tags" \
        -c 50 \
        -severity critical,high,medium \
        -o "$RESULTS_DIR/nuclei_results.txt" \
        -jsonl "$RESULTS_DIR/nuclei_results.jsonl" \
        -stats -silent || warn "Nuclei completed with possible errors."

    if [[ -s "$RESULTS_DIR/nuclei_results.txt" ]]; then
        log "Nuclei found potential issues! Review nuclei_results.txt and nuclei_results.jsonl"
    else
        log "No issues found by Nuclei."
    fi
}

run_metasploit() {
    if ! command -v msfconsole &> /dev/null; then
        warn "Metasploit not found. Skipping MSF integration."
        return
    fi

    local rc_file="$RESULTS_DIR/metasploit.rc"
    local msf_log="$RESULTS_DIR/metasploit.log"

    log "Generating Metasploit resource script..."

    > "$rc_file"

    echo "db_import $RESULTS_DIR/nmap_full.xml" >> "$rc_file"
    echo "hosts -o $RESULTS_DIR/msf_hosts.txt" >> "$rc_file"
    echo "services -o $RESULTS_DIR/msf_services.txt" >> "$rc_file"

    if grep -q "80/open\|443/open\|8080/open\|8443/open" "$RESULTS_DIR/nmap_full.txt" 2>/dev/null; then
        log "Adding HTTP auxiliary scanners..."
        cat >> "$rc_file" <<EOF
use auxiliary/scanner/http/http_version
set RHOSTS $TARGET
run
use auxiliary/scanner/http/dir_listing
set RHOSTS $TARGET
run
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS $TARGET
run
EOF
        [[ $MSF_AGGRESSIVE == true ]] && cat >> "$rc_file" <<EOF
use auxiliary/scanner/http/ssl_params
set RHOSTS $TARGET
run
use auxiliary/scanner/http/robots_txt
set RHOSTS $TARGET
run
EOF
    fi

    if grep -q "139/open\|445/open" "$RESULTS_DIR/nmap_full.txt" 2>/dev/null; then
        log "Adding SMB auxiliary scanners..."
        cat >> "$rc_file" <<EOF
use auxiliary/scanner/smb/smb_version
set RHOSTS $TARGET
run
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS $TARGET
run
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS $TARGET
run
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS $TARGET
run
EOF
    fi

    if [[ -f "$RESULTS_DIR/snmp_valid_communities.txt" ]]; then
        local community=$(head -n1 "$RESULTS_DIR/snmp_valid_communities.txt")
        log "Adding SNMP enum with community '$community'..."
        cat >> "$rc_file" <<EOF
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS $TARGET
set COMMUNITY $community
run
EOF
    fi

    echo "spool $msf_log" >> "$rc_file"
    echo "exit" >> "$rc_file"

    log "Running Metasploit automation (this may take a while)..."
    msfconsole -q -r "$rc_file" > /dev/null 2>&1 || warn "Metasploit completed (check $msf_log for details)"

    log "Metasploit automation complete. Full log: $msf_log"
}

# ==================== MAIN EXECUTION ====================

log "Starting modular pentest on $TARGET"

# DNS Enumeration
if [[ $RUN_DNS == true ]] && is_domain; then
    run_dns_enum
elif [[ $RUN_DNS == true ]] && ! is_domain; then
    warn "Target appears to be an IP address. Skipping DNS enumeration."
fi

# Nmap
[[ $RUN_NMAP == true ]] && run_nmap

# Web services (Nikto + Gobuster)
if [[ $RUN_NIKTO == true || $RUN_GOBUSTER == true ]]; then
    if [[ $RUN_NMAP == false && ! -f "$RESULTS_DIR/nmap_full.txt" ]]; then
        error "Web scans require Nmap results."
        exit 1
    fi
    scan_web_services
fi

# SMB
[[ $RUN_SMB == true ]] && scan_smb

# SNMP
[[ $RUN_SNMP == true ]] && scan_snmp

# Nuclei
if [[ $RUN_NUCLEI == true ]]; then
    if [[ ! -f "$RESULTS_DIR/nmap_full.txt" ]]; then
        error "Nuclei requires Nmap results for web port detection."
        exit 1
    fi
    scan_nuclei
fi

# Metasploit
if [[ $RUN_MSF == true ]]; then
    if [[ ! -f "$RESULTS_DIR/nmap_full.xml" ]]; then
        error "Metasploit integration requires Nmap XML output."
        exit 1
    fi
    run_metasploit
fi

log "Scan complete! All results saved in: $RESULTS_DIR"
log "Key files to review:"
log "  - nmap_full.txt / nmap_full.xml"
log "  - nikto_*.txt & gobuster_*.txt"
log "  - nuclei_results.txt / nuclei_results.jsonl (if --nuclei used)"
log "  - metasploit.log (if --msf used)"
log "  - dnsrecon_*, fierce.txt, enum4linux.txt, snmp-*.txt"
log ""
log "Remember: Use this script only for authorized penetration testing!"

exit 0
