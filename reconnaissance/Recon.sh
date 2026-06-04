#!/bin/bash
# Safe Modular Reconnaissance Script - Kali Linux
# Enumeration & Vulnerability Discovery ONLY (no exploitation)
# Professional HTML report with accurate CVSS scoring
# Usage: sudo ./recon.sh <target> [options]
set -euo pipefail

# === Config ===
TARGET=""
RUN_NMAP=true RUN_NIKTO=true RUN_GOBUSTER=true
RUN_SMB=true RUN_DNS=true RUN_SNMP=true
RUN_NUCLEI=true
NUCLEI_AGGRESSIVE=false

NMAP_AGGRESSIVE=false NMAP_STEALTH=false
NMAP_FRAGMENT=false NMAP_DECOY="" NMAP_SPOOF_MAC=false
NMAP_DATA_LENGTH=0 NMAP_BADSUM=false

GOBUSTER_STEALTH=false GOBUSTER_DELAY="0ms"
GOBUSTER_THREADS=50 GOBUSTER_PROXY=""

GENERATE_HTML=true

WORDLIST="/usr/share/wordlists/dirb/common.txt"
DNS_WORDLIST="/usr/share/wordlists/dnsrecon/namelist.txt"
SNMP_WORDLIST="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt"

DATE=$(date +%Y-%m-%d_%H-%M)
TIMESTAMP=$(date '+%B %d, %Y at %H:%M')

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' NC='\033[0m'
log() { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[-] $1${NC}"; }
error() { echo -e "${RED}[!] $1${NC}"; exit 1; }

usage() { grep "^#" "$0" | cut -c 4-; exit 1; }

# === Argument parsing ===
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        --no-nmap|--no-nikto|--no-gobuster|--no-smb|--no-dns|--no-snmp|--no-nuclei)
            eval "$(echo "$1" | tr - _ | cut -c3-)=false" ;;
        --no-html) GENERATE_HTML=false ;;
        --nuclei-aggressive) NUCLEI_AGGRESSIVE=true ;;
        --aggressive) NMAP_AGGRESSIVE=true ;;
        --stealth) NMAP_STEALTH=true ;;
        --fragment) NMAP_FRAGMENT=true ;;
        --decoy) NMAP_DECOY="$2"; shift ;;
        --spoof-mac) NMAP_SPOOF_MAC=true ;;
        --data-length) NMAP_DATA_LENGTH="$2"; shift ;;
        --badsum) NMAP_BADSUM=true ;;
        --gobuster-stealth) GOBUSTER_STEALTH=true ;;
        --gobuster-delay) GOBUSTER_DELAY="$2"; shift ;;
        --gobuster-threads) GOBUSTER_THREADS="$2"; shift ;;
        --gobuster-proxy) GOBUSTER_PROXY="$2"; shift ;;
        --wordlist|--dns-wordlist|--snmp-wordlist) eval "$(echo $1 | tr - _ | cut -c3-)= \"$2\""; shift ;;
        --all) RUN_NMAP=RUN_NIKTO=RUN_GOBUSTER=RUN_SMB=RUN_DNS=RUN_SNMP=RUN_NUCLEI=true ;;
        -*|--*) error "Unknown option: $1" ;;
        *) TARGET="$1" ;;
    esac
    shift
done

[[ -z "$TARGET" ]] && error "No target specified"

# Sanitize target for directory name
SAFE_TARGET=$(echo "$TARGET" | tr -cd '[:alnum:]._-' | tr '/' '_')
RESULTS_DIR="recon_${SAFE_TARGET}_${DATE}"
mkdir -p "$RESULTS_DIR"
HTML_REPORT="$RESULTS_DIR/report.html"
VULN_JSON="$RESULTS_DIR/findings.json"

log "Safe reconnaissance → $RESULTS_DIR"

# === Helpers ===
is_domain() { [[ "$TARGET" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && ! [[ "$TARGET" =~ / ]]; }

build_nmap_evasion() {
    local opts=""
    [[ $NMAP_STEALTH == true || $NMAP_FRAGMENT == true ]] && opts+="-f "
    [[ -n "$NMAP_DECOY" ]] && opts+="-D $NMAP_DECOY "
    [[ $NMAP_STEALTH == true || $NMAP_SPOOF_MAC == true ]] && opts+="--spoof-mac 0 "
    [[ $NMAP_STEALTH == true ]] && opts+="--data-length 24 "
    [[ $NMAP_DATA_LENGTH -gt 0 ]] && opts+="--data-length $NMAP_DATA_LENGTH "
    [[ $NMAP_STEALTH == true || $NMAP_BADSUM == true ]] && opts+="--badsum "
    [[ $NMAP_STEALTH == true ]] && opts+="-T2 "
    echo "$opts"
}

# === Finding Tracking (CVSS v3.1) ===
echo '[]' > "$VULN_JSON"

add_finding() {
    local title="$1" cvss_score="$2" vector="$3" description="$4" evidence="$5" module="$6"
    local port="${7:-null}" recommendation="${8:-"Review and apply appropriate mitigation."}"

    local severity="None"
    if (( $(awk "BEGIN {print ($cvss_score >= 9.0)}") )); then severity="Critical"; fi
    if (( $(awk "BEGIN {print ($cvss_score >= 7.0 && $cvss_score < 9.0)}") )); then severity="High"; fi
    if (( $(awk "BEGIN {print ($cvss_score >= 4.0 && $cvss_score < 7.0)}") )); then severity="Medium"; fi
    if (( $(awk "BEGIN {print ($cvss_score > 0.0 && $cvss_score < 4.0)}") )); then severity="Low"; fi

    local tmp=$(mktemp)
    jq --arg t "$title" --argjson s "$cvss_score" --arg v "$vector" --arg sev "$severity" \
       --arg d "$description" --arg e "$evidence" --arg m "$module" --argjson p "$port" \
       --arg r "$recommendation" \
       '. += [{title: $t, cvss: $s, vector: $v, severity: $sev, description: $d, evidence: $e, module: $m, port: $p, recommendation: $r}]' \
       "$VULN_JSON" > "$tmp" && mv "$tmp" "$VULN_JSON"
}

# === Modules ===

run_dns_enum() {
    [[ ! $(is_domain) ]] && { warn "IP target → skipping DNS"; return; }
    log "DNS enumeration"
    dnsrecon -d "$TARGET" -t std --lifetime 10 -v > "$RESULTS_DIR/dnsrecon_full.txt" 2>/dev/null || true
    [[ -f "$DNS_WORDLIST" ]] && dnsrecon -d "$TARGET" -D "$DNS_WORDLIST" -t brt > "$RESULTS_DIR/dnsrecon_bruteforce.txt" 2>/dev/null || true
    fierce --domain "$TARGET" --subdomains "$DNS_WORDLIST" --threads 20 > "$RESULTS_DIR/fierce.txt" 2>/dev/null || true
}

run_nmap() {
    log "Nmap port scan"
    local evasion=$(build_nmap_evasion)
    nmap -sS -sU --top-ports 1000 -Pn $evasion \
        -oN "$RESULTS_DIR/nmap_initial.txt" -oX "$RESULTS_DIR/nmap_initial.xml" "$TARGET" > /dev/null || warn "Initial scan failed"

    [[ ! -s "$RESULTS_DIR/nmap_initial.txt" ]] && return

    grep "^[0-9].*/open" "$RESULTS_DIR/nmap_initial.txt" | cut -d'/' -f1 > "$RESULTS_DIR/open_tcp_ports.txt" 2>/dev/null || touch "$RESULTS_DIR/open_tcp_ports.txt"
    ports=$(tr '\n' ',' < "$RESULTS_DIR/open_tcp_ports.txt" | sed 's/,$//')

    if [[ -n "$ports" ]]; then
        local det_evasion=""; [[ $NMAP_STEALTH == true ]] && det_evasion="-f --data-length 10 -T3"
        nmap -sV -sC -p "$ports" -Pn $det_evasion \
            -oN "$RESULTS_DIR/nmap_detailed.txt" -oX "$RESULTS_DIR/nmap_detailed.xml" "$TARGET" > /dev/null || warn "Detailed scan failed"
        cp "$RESULTS_DIR/nmap_detailed"* "$RESULTS_DIR/nmap_full"* 2>/dev/null || true
    fi

    [[ $NMAP_AGGRESSIVE == true ]] && {
        log "Full aggressive scan"
        nmap -A -p- -Pn $evasion -oN "$RESULTS_DIR/nmap_full_aggressive.txt" "$TARGET" || true
    }
}

run_nikto() {
    local url=$1 port=$2
    log "Nikto on $url"
    nikto -h "$url" -o "$RESULTS_DIR/nikto_port${port}.txt" || true

    local file="$RESULTS_DIR/nikto_port${port}.txt"
    [[ ! -s "$file" ]] && return

    while IFS= read -r line; do
        [[ "$line" != +* ]] && continue
        desc=$(echo "$line" | sed 's/^[+] //; s/ (OSVDB-[0-9]*)//')

        case "$line" in
            *"Heartbleed"*) add_finding "Potential Heartbleed Vulnerability" 9.8 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" "Detected via Nikto" "$line" "Nikto" "$port" "Verify and patch OpenSSL" ;;
            *"SSLv2"*) add_finding "SSLv2 Supported" 7.5 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" "Deprecated protocol" "$line" "Nikto" "$port" "Disable SSLv2" ;;
            *"Directory listing"*) add_finding "Directory Listing Enabled" 7.5 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" "Sensitive files may be browsable" "$line" "Nikto" "$port" "Disable directory indexing" ;;
            *"phpinfo()"*) add_finding "PHPInfo Exposed" 8.8 "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" "Full configuration disclosure" "$line" "Nikto" "$port" "Remove phpinfo.php" ;;
            *) add_finding "Web Misconfiguration: $desc" 4.3 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" "General finding" "$line" "Nikto" "$port" ;;
        esac
    done < "$file"
}

run_gobuster() {
    local url=$1 port=$2
    log "Gobuster on $url"
    local opts="-t $GOBUSTER_THREADS -q --timeout 20s"
    [[ $GOBUSTER_STEALTH == true ]] && opts+=" --random-agent --delay 1000ms -t 5"
    [[ "$GOBUSTER_DELAY" != "0ms" ]] && opts+=" --delay $GOBUSTER_DELAY"
    [[ -n "$GOBUSTER_PROXY" ]] && opts+=" --proxy $GOBUSTER_PROXY"
    gobuster dir -u "$url" -w "$WORDLIST" $opts -o "$RESULTS_DIR/gobuster_port${port}.txt" || true

    local file="$RESULTS_DIR/gobuster_port${port}.txt"
    [[ ! -s "$file" ]] && return

    while IFS= read -r line; do
        [[ ! "$line" =~ Status:\ (200|301|302) ]] && continue
        path=$(echo "$line" | awk '{print $2}')

        case "$path" in
            */.git*) add_finding "Potential .git Directory Exposure" 9.1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" "Source code may be accessible" "$line" "Gobuster" "$port" "Remove .git from production" ;;
            *.env|*config*) add_finding "Potential Config File Exposure" 8.8 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" "Credentials may be leaked" "$line" "Gobuster" "$port" "Block access" ;;
            */admin*) add_finding "Admin Interface Discovered" 7.1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" "Potential management panel" "$line" "Gobuster" "$port" "Restrict access" ;;
            *.bak|*.old|*.~) add_finding "Backup File Found" 7.5 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" "May contain source" "$line" "Gobuster" "$port" "Remove backups" ;;
            *) add_finding "Interesting Path: $path" 3.1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" "May warrant review" "$line" "Gobuster" "$port" ;;
        esac
    done < "$file"
}

scan_web_services() {
    local xml_file="$RESULTS_DIR/nmap_full.xml"
    [[ ! -f "$xml_file" ]] && { warn "No Nmap XML → skipping web scans"; return; }
    tmp_xsl=$(mktemp)
    cat > "$tmp_xsl" <<'XSL'
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text"/>
<xsl:template match="/">
  <xsl:for-each select="//port[state/@state='open' and (portid=80 or portid=443 or portid=8080 or portid=8000 or portid=8443 or portid=3000 or portid=5000 or portid=9000)]">
    <xsl:value-of select="portid"/><xsl:text> </xsl:text>
  </xsl:for-each>
</xsl:template>
</xsl:stylesheet>
XSL
    ports=$(xsltproc "$tmp_xsl" "$xml_file" 2>/dev/null | tr ' ' '\n' | sort -u | grep -v '^$' || echo "")
    rm -f "$tmp_xsl"

    [[ -z "$ports" ]] && { warn "No common web ports found"; return; }
    log "Web ports: $ports"

    for port in $ports; do
        proto="http"; [[ $port -eq 443 || $port -eq 8443 ]] && proto="https"
        url="${proto}://$TARGET:$port"
        [[ $RUN_NIKTO == true ]] && run_nikto "$url" "$port"
        [[ $RUN_GOBUSTER == true ]] && run_gobuster "$url" "$port"
    done
}

scan_smb() {
    grep -qE "(139|445)/open" "$RESULTS_DIR/nmap_full.txt" 2>/dev/null || return
    log "SMB ports open → enum4linux"
    enum4linux -a "$TARGET" > "$RESULTS_DIR/enum4linux.txt" 2>/dev/null || true

    local file="$RESULTS_DIR/enum4linux.txt"
    [[ ! -s "$file" ]] && return

    grep -qi "null session" "$file" && \
        add_finding "SMB Null Sessions Possible" 9.1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" \
            "Anonymous access detected" "enum4linux output" "SMB" null "Disable null sessions"

    grep -qi "signing.*disabled" "$file" && \
        add_finding "SMB Signing Not Enforced" 8.1 "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" \
            "Potential relay attacks" "enum4linux output" "SMB" null "Enable SMB signing"

    while IFS= read -r share; do
        [[ -z "$share" ]] && continue
        add_finding "World-Readable SMB Share Detected" 6.5 \
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" \
            "Weak share permissions" "$share" "SMB" null "Restrict permissions"
    done < <(grep -iE "share.*(everyone|world|guest)" "$file")
}

scan_snmp() {
    local open=""
    if command -v xsltproc &>/dev/null && [[ -f "$RESULTS_DIR/nmap_full.xml" ]]; then
        tmp_snmp_xsl=$(mktemp)
cat > "$tmp_snmp_xsl" <<'SNMPXSL'
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text"/>
<xsl:template match="/"><xsl:if test="//port[protocol='udp' and portid=161 and state/@state='open']">open</xsl:if></xsl:template>
</xsl:stylesheet>
SNMPXSL
open=$(xsltproc "$tmp_snmp_xsl" "$RESULTS_DIR/nmap_full.xml" 2>/dev/null || echo "")
rm -f "$tmp_snmp_xsl"
    else
        grep -q "161/udp.*open" "$RESULTS_DIR/nmap_full.txt" 2>/dev/null && open="open"
    fi

    [[ -z "$open" ]] && return

    log "SNMP 161/udp open → community brute"
    [[ -f "$SNMP_WORDLIST" ]] || { warn "SNMP wordlist missing"; return; }
    onesixtyone -c "$SNMP_WORDLIST" -w 50 -t 5 "$TARGET" > "$RESULTS_DIR/onesixtyone.txt" 2>/dev/null || true

    local file="$RESULTS_DIR/onesixtyone.txt"
    [[ ! -s "$file" ]] && return

    communities=$(grep -v "Waiting" "$file" | awk '{print $2}' | tr -d '[]' | sort -u)
    [[ -n "$communities" ]] && add_finding "SNMP Community Strings Found" 7.5 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" \
        "Communities: $communities" "onesixtyone output" "SNMP" 161 "Use strong strings or disable SNMP"
}

scan_nuclei() {
    command -v nuclei &>/dev/null || { warn "Nuclei not installed"; return; }

    local urls="$RESULTS_DIR/nuclei_urls.txt"; > "$urls"
    ports=$(grep -E "(80|443|8080|8000|8443|3000|5000|9000)/open" "$RESULTS_DIR/nmap_full.txt" 2>/dev/null | cut -d'/' -f1 || echo "")
    [[ -z "$ports" ]] && { warn "No web ports for Nuclei"; return; }

    for p in $ports; do
        echo "http$( [[ $p -eq 443 || $p -eq 8443 ]] && echo s )://$TARGET:$p" >> "$urls"
    done

    tags="misconfiguration,exposed,default-login,fuzz"
    [[ $NUCLEI_AGGRESSIVE == true ]] && tags+=",cve"
    log "Running Nuclei scan"
    nuclei -l "$urls" -tags "$tags" -severity critical,high,medium -o "$RESULTS_DIR/nuclei_results.txt" -silent || true

    local file="$RESULTS_DIR/nuclei_results.txt"
    [[ ! -s "$file" ]] && return

    while IFS= read -r line; do
        if [[ "$line" =~ \[([a-z]+)\]\ \[([^]]+)\]\ (http[^:]+:([0-9]+)) ]]; then
            sev_raw="${BASH_REMATCH[1]^^}"
            template="${BASH_REMATCH[2]}"
            url="${BASH_REMATCH[3]}"
            port="${BASH_REMATCH[4]}"
            case "$sev_raw" in
                CRITICAL) score=9.5; vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";;
                HIGH)     score=8.2; vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";;
                MEDIUM)   score=5.9; vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N";;
                *)        score=3.7; vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N";;
            esac
            add_finding "Potential Issue: $template" "$score" "$vector" "Detected on $url" "$line" "Nuclei" "$port"
        fi
    done < "$file"
}

# === HTML Report ===
generate_html_report() {
    [[ $GENERATE_HTML == false ]] && return
    log "Generating HTML report → $HTML_REPORT"

    cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report - $TARGET</title>
<style>
    body {font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; color: #333;}
    h1, h2 {color: #2c3e50;}
    table {width: 100%; border-collapse: collapse; margin: 20px 0;}
    th, td {padding: 12px; border: 1px solid #ddd; text-align: left;}
    th {background: #34495e; color: white;}
    tr:nth-child(even) {background: #f9f9f9;}
    .critical {background: #ffcccc;}
    .high {background: #ff9999;}
    .medium {background: #fff3cd;}
    .low {background: #d4edda;}
    pre {background: #2c2c2c; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto;}
    .section {background: white; padding: 20px; border-radius: 8px; margin-bottom: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);}
    .risk-banner {font-size: 2.2em; text-align: center; padding: 30px; border-radius: 12px; margin: 30px 0; font-weight: bold;}
</style>
</head>
<body>
<h1>Reconnaissance Report - $TARGET</h1>
<p><strong>Generated:</strong> $TIMESTAMP</p>
<p><em>Enumeration and discovery only — no exploitation performed</em></p>
<hr>
EOF

    highest=$(jq -r 'max_by(.cvss)?.cvss // 0' "$VULN_JSON")
    risk_level="Low"; banner_color="#d4edda"
    awk "BEGIN {exit !($highest >= 9.0)}" && risk_level="Critical" && banner_color="#ffcccc"
    awk "BEGIN {exit !($highest >= 7.0 && $highest < 9.0)}" && risk_level="High" && banner_color="#ff9999"
    awk "BEGIN {exit !($highest >= 4.0 && $highest < 7.0)}" && risk_level="Medium" && banner_color="#fff3cd"

    echo "<div class='risk-banner' style='background:$banner_color;'>
        Highest CVSS: <strong>$highest</strong> → $risk_level Risk<br>
        $(jq length "$VULN_JSON") potential findings identified
    </div>" >> "$HTML_REPORT"

    echo "<div class='section'><h2>Prioritized Potential Risks</h2><table>
<tr><th>CVSS</th><th>Severity</th><th>Finding</th><th>Module</th><th>Port</th><th>Recommendation</th></tr>" >> "$HTML_REPORT"

    jq -r 'sort_by(.cvss) | reverse[] | "<tr class=\"\(.severity | ascii_downcase)\"><td><strong>\(.cvss)</strong></td><td>\(.severity)</td><td>\(.title)</td><td>\(.module)</td><td>\(.port // \"-\")</td><td>\(.recommendation)</td></tr>"' "$VULN_JSON" >> "$HTML_REPORT"

    [[ $(jq length "$VULN_JSON") -eq 0 ]] && echo "<tr><td colspan='6' style='text-align:center; color:#777;'>No significant potential risks found</td></tr>" >> "$HTML_REPORT"

    echo "</table></div><hr><p><em>Authorized use only. Manual verification recommended.</em></p></body></html>" >> "$HTML_REPORT"

    log "Report generated: $HTML_REPORT"
}

# === Main ===
log "Starting recon on $TARGET"

[[ $RUN_DNS == true ]] && run_dns_enum
[[ $RUN_NMAP == true ]] && run_nmap
[[ $RUN_NIKTO == true || $RUN_GOBUSTER == true ]] && scan_web_services
[[ $RUN_SMB == true ]] && scan_smb
[[ $RUN_SNMP == true ]] && scan_snmp
[[ $RUN_NUCLEI == true ]] && scan_nuclei

generate_html_report

log "Recon complete → $RESULTS_DIR"
[[ $GENERATE_HTML == true ]] && log "Open report: file://$(realpath "$HTML_REPORT")"
log "Use only with explicit authorization!"
exit 0
