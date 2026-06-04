#!/bin/bash

# SSL/TLS Security Audit
# Deep SSL/TLS analysis — certificate chains, cipher suites, protocol versions, vulnerabilities
# Usage: ./ssl_tls_audit.sh <host> [-p port] [-o output_dir] [-j]
# Requires: openssl, curl, testssl.sh (optional)
# Disclaimer: For authorized testing only

set -euo pipefail

TARGET="${1:-}"
PORT="${2:-443}"
OUTPUT_DIR=""
JSON_OUTPUT=false

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'
log()   { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn()  { echo -e "${YELLOW}[-] $1${NC}"; }
found() { echo -e "${GREEN}[✓] $1${NC}"; }
fail()  { echo -e "${RED}[!] $1${NC}"; }

usage() {
    head -4 "$0" | cut -c4-
    echo ""
    echo "Options:"
    echo "  -p, --port PORT    Target port (default: 443)"
    echo "  -o, --output DIR   Output directory"
    echo "  -j, --json         JSON output"
    echo "  -h, --help         Show this help"
    echo ""
    echo "Example:"
    echo "  $0 example.com -p 8443 -o ssl_audit_example"
    echo "  $0 192.168.1.100 -p 443 -j"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port) PORT="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -j|--json) JSON_OUTPUT=true; shift ;;
        -h|--help) usage ;;
        *) TARGET="$1"; shift ;;
    esac
done

[[ -z "$TARGET" ]] && usage

[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="ssl_audit_${TARGET}_${PORT}_$(date +%Y-%m-%d)"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/ssl_audit.log"
JSON_FILE="$OUTPUT_DIR/results.json"
CERT_FILE="$OUTPUT_DIR/certificate.txt"
CIPHER_FILE="$OUTPUT_DIR/ciphers.txt"
PROTO_FILE="$OUTPUT_DIR/protocols.txt"
VULN_FILE="$OUTPUT_DIR/vulnerabilities.txt"

log "Starting SSL/TLS audit → $TARGET:$PORT"

# ─── Helper functions ───
run_openssl() {
    openssl s_client -connect "$TARGET:$PORT" -servername "$TARGET" "$@" </dev/null 2>/dev/null
}

json_init() {
    echo "{" > "$JSON_FILE"
    echo "  \"target\": \"$TARGET\", " >> "$JSON_FILE"
    echo "  \"port\": $PORT, " >> "$JSON_FILE"
    echo "  \"timestamp\": \"$(date -I)\"," >> "$JSON_FILE"
    echo "  \"vulnerabilities\": [], " >> "$JSON_FILE"
    echo "  \"protocols\": {}, " >> "$JSON_FILE"
    echo "  \"ciphers\": [], " >> "$JSON_FILE"
    echo "  \"certificate\": {}" >> "$JSON_FILE"
    echo "}" >> "$JSON_FILE"
}

json_update() {
    local key="$1"; local value="$2"
    sed -i "s/\"$key\": [0-9]*\$/\"$key\": $value/" "$JSON_FILE" 2>/dev/null || true
}

json_add_vuln() {
    local name="$1"; local severity="$2"; local score="$3"; local desc="$4"
    local tmp=$(mktemp)
    jq --arg n "$name" --arg s "$severity" --argjson sc "$score" --arg d "$desc" \
        '.vulnerabilities += [{name: $n, severity: $s, cvss: sc, description: $d}]' \
        "$JSON_FILE" > "$tmp" && mv "$tmp" "$JSON_FILE"
}

# ═══════════════════════════════════════════════════════════
# PHASE 1: Certificate analysis
# ═══════════════════════════════════════════════════════════
log "Phase 1: Certificate analysis"

cert_output=$(run_openssl </dev/null 2>/dev/null | head -50)
echo "$cert_output" > "$CERT_FILE"

if echo "$cert_output" | grep -q "BEGIN CERTIFICATE"; then
    # Extract certificate details
    subject=$(echo "$cert_output" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
    issuer=$(echo "$cert_output" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
    serial=$(echo "$cert_output" | openssl x509 -noout -serial 2>/dev/null | sed 's/serial=//')
    not_before=$(echo "$cert_output" | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//')
    not_after=$(echo "$cert_output" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    san=$(echo "$cert_output" | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -v "subjectAltName")
    fingerprint=$(echo "$cert_output" | openssl x509 -noout -fingerprint -sha256 2>/dev/null)

    log "  Subject: $subject"
    log "  Issuer: $issuer"
    log "  Valid: $not_before → $not_after"
    [[ -n "$san" ]] && log "  SANs: $(echo "$san" | tr '\n' ' ')"
    log "  SHA256: $fingerprint"

    # Check expiry
    expiry_date=$(echo "$cert_output" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

    if [[ $days_left -lt 0 ]]; then
        fail "  Certificate EXPIRED ${days_left#-} days ago!"
        json_add_vuln "Expired Certificate" "HIGH" 7.5 "Certificate expired on $not_after"
    elif [[ $days_left -lt 30 ]]; then
        warn "  Certificate expires in $days_left days"
        json_add_vuln "Certificate Expiring Soon" "MEDIUM" 5.0 "Certificate expires in $days_left days"
    else
        found "  Certificate valid for $days_left more days"
    fi

    # Self-signed check
    if echo "$subject" | grep -q "$issuer"; then
        warn "  Self-signed certificate detected"
        json_add_vuln "Self-Signed Certificate" "LOW" 4.0 "Certificate is self-signed — not trusted by browsers"
    fi

    # Weak signature algorithm
    sig_algo=$(echo "$cert_output" | openssl x509 -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1)
    if echo "$sig_algo" | grep -qi "md5\|sha1\|md2"; then
        fail "  WEAK signature algorithm: $sig_algo"
        json_add_vuln "Weak Certificate Signature" "HIGH" 7.5 "MD5/SHA1 signatures are deprecated and vulnerable to collision attacks"
    fi

    # Check key size
    key_size=$(echo "$cert_output" | openssl x509 -noout -text 2>/dev/null | grep "Public-Key" | head -1)
    if echo "$key_size" | grep -q "2048\|4096"; then
        found "  Key size: OK ($key_size)"
    elif echo "$key_size" | grep -q "1024\|512"; then
        warn "  SMALL key size: $key_size"
        json_add_vuln "Weak Key Size" "MEDIUM" 5.3 "Key size $key_size is considered weak"
    fi
else
    warn "  Could not retrieve certificate"
fi

# ─── Chain analysis ───
log "  Checking certificate chain..."
chain_output=$(run_openssl -showcerts </dev/null 2>/dev/null)
chain_count=$(echo "$chain_output" | grep -c "BEGIN CERTIFICATE" || echo 0)
log "  Chain contains $chain_count certificate(s)"

if [[ "$chain_count" -eq 1 ]]; then
    warn "  Incomplete chain — only leaf cert provided"
    json_add_vuln "Incomplete Certificate Chain" "MEDIUM" 5.3 "Server only provides leaf certificate — chain may be incomplete"
elif [[ "$chain_count" -gt 1 ]]; then
    found "  Full chain: $chain_count certificates"
fi

# ═══════════════════════════════════════════════════════════
# PHASE 2: Protocol checks
# ═══════════════════════════════════════════════════════════
log "Phase 2: Protocol version checks"

> "$PROTO_FILE"
PROTOCOLS_SUPPORTED=()

for proto in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
    result=$(echo "" | openssl s_client -connect "$TARGET:$PORT" -"$proto" 2>&1 | grep -E "Protocol|error|handshake")

    if echo "$result" | grep -qi "Protocol.*$proto\|SSL-Session\|Protocol version"; then
        found "  $proto: SUPPORTED"
        echo "$proto: SUPPORTED" >> "$PROTO_FILE"
        PROTOCOLS_SUPPORTED+=("$proto")

        # Flag weak protocols
        case "$proto" in
            ssl2|ssl3)
                fail "  $proto is WEAK and deprecated!"
                json_add_vuln "$proto Enabled" "CRITICAL" 9.8 "$proto is vulnerable to multiple attacks (POODLE, BEAST, etc.)"
                ;;
            tls1)
                warn "  $proto is deprecated"
                json_add_vuln "$proto Enabled (Deprecated)" "HIGH" 7.5 "$proto is deprecated and weak"
                ;;
            tls1_1)
                warn "  $proto is deprecated"
                json_add_vuln "$proto Enabled (Deprecated)" "MEDIUM" 6.5 "$proto is deprecated"
                ;;
        esac
    elif echo "$result" | grep -qi "no such file\|unknown option\|wrong\|error"; then
        echo "  $proto: not tested ($result)" >> "$PROTO_FILE"
    else
        echo "  $proto: not supported or rejected" >> "$PROTO_FILE"
    fi
done

# ═══════════════════════════════════════════════════════════
# PHASE 3: Cipher suite enumeration
# ═══════════════════════════════════════════════════════════
log "Phase 3: Cipher suite enumeration"

> "$CIPHER_FILE"
CIPHER_COUNT=0
WEAK_CIPHERS=0

# Get list of all ciphers
openssl ciphers -v 'ALL:COMPLEMENTOFALL:@STRENGTH' 2>/dev/null | while read -r line; do
    cipher_name=$(echo "$line" | awk '{print $1}')
    cipher_bits=$(echo "$line" | awk '{print $2}')
    cipher_type=$(echo "$line" | awk '{print $3}')

    # Test each cipher individually
    test_result=$(echo "" | openssl s_client -connect "$TARGET:$PORT" -cipher "$cipher_name" 2>&1 | head -5)

    if echo "$test_result" | grep -qi "Cipher is|SSL-Session\|done"; then
        echo "$line" >> "$CIPHER_FILE"
        ((CIPHER_COUNT++))
        # Flag weak ciphers
        if echo "$line" | grep -qiE "NULL|aNULL|EXP|RC4|3DES|MD5|SHA1"; then
            warn "  WEAK: $cipher_name"
            ((WEAK_CIPHERS++))
        fi
    fi
done 2>/dev/null || true

CIPHER_COUNT=$(wc -l < "$CIPHER_FILE" 2>/dev/null || echo 0)
WEAK_CIPHERS=$(grep -cE "NULL|aNULL|EXP|RC4|3DES|MD5|SHA1" "$CIPHER_FILE" 2>/dev/null || echo 0)

log "  Found $CIPHER_COUNT ciphers, $WEAK_CIPHERS weak/broken"

if [[ "$WEAK_CIPHERS" -gt 0 ]]; then
    warn "  $WEAK_CIPHERS weak ciphers detected — vulnerable to cipher downgrade attacks"
    json_add_vuln "Weak Cipher Suites Enabled" "HIGH" 7.5 "Multiple weak ciphers enabled — susceptible to downgrade attacks"
fi

# Check for perfect forward secrecy
if grep -q "ECDHE\|DHE\|CHACHA20" "$CIPHER_FILE"; then
    found "  Forward secrecy: SUPPORTED (ECDHE/DHE)"
else
    warn "  Forward secrecy: NOT supported — no PFS ciphers"
    json_add_vuln "No Forward Secrecy" "MEDIUM" 5.3 "No ephemeral key exchange — traffic may be decryptable if key is compromised"
fi

# ═══════════════════════════════════════════════════════════
# PHASE 4: Vulnerability checks
# ═══════════════════════════════════════════════════════════
log "Phase 4: Vulnerability checks"

> "$VULN_FILE"
VULN_COUNT=0

# Heartbleed
log "  Checking Heartbleed..."
hb_result=$(echo "" | openssl s_client -connect "$TARGET:$PORT" -tls1_2 2>&1 | grep -qi "heartbeat" && echo "VULNERABLE" || echo "SAFE")
if [[ "$hb_result" == "VULNERABLE" ]]; then
    fail "  Heartbleed: VULNERABLE"
    echo "Heartbleed: VULNERABLE" >> "$VULN_FILE"
    json_add_vuln "OpenSSL Heartbleed" "CRITICAL" 9.8 "Memory disclosure via heartbeat extension"
    ((VULN_COUNT++))
else
    found "  Heartbleed: safe"
fi

# POODLE (SSLv3)
log "  Checking POODLE..."
if echo "" | openssl s_client -connect "$TARGET:$PORT" -ssl3 2>&1 | grep -qi "ssl3_get_record\|wrong version\|handshake\|alert"; then
    fail "  POODLE (SSLv3): VULNERABLE or rejected"
    json_add_vuln "POODLE (SSLv3)" "HIGH" 7.5 "SSLv3 enabled — vulnerable to POODLE attack"
    ((VULN_COUNT++))
else
    found "  POODLE: SSLv3 not exploitable"
fi

# TLS POODLE
log "  Checking TLS POODLE..."
poodle_check=$(echo "" | openssl s_client -connect "$TARGET:$PORT" -tls1_2 -tlsextcmd "STATUS_REQUEST" 2>&1 | head -10)
if echo "$poodle_check" | grep -qi "CBC"; then
    warn "  TLS POODLE: potential CBC vulnerability"
    json_add_vuln "TLS POODLE" "MEDIUM" 6.0 "TLS CBC mode vulnerability"
    ((VULN_COUNT++))
fi

# BEAST
log "  Checking BEAST (TLS 1.0 CBC)..."
if grep -q "TLSv1 " "$PROTO_FILE"; then
    warn "  BEAST: TLS 1.0 enabled (CBC vulnerable)"
    json_add_vuln "BEAST Attack Possible" "MEDIUM" 6.0 "TLS 1.0 with CBC cipher vulnerable to BEAST"
    ((VULN_COUNT++))
fi

# ROBOT (TLS RSA padding oracle)
log "  Checking ROBOT..."
robot_result=$(echo "" | openssl s_client -connect "$TARGET:$PORT" -tls1_2 2>&1 | grep -i "RSA padding\|error\|alert\|wrong")
if echo "$robot_result" | grep -qi "padding\|oracle\|error"; then
    warn "  ROBOT: potential padding oracle"
    json_add_vuln "ROBOT Attack" "HIGH" 7.5 "TLS RSA padding oracle vulnerability"
    ((VULN_COUNT++))
else
    found "  ROBOT: not detected"
fi

# Logjam
log "  Checking Logjam..."
logjam_result=$(echo "" | openssl s_client -connect "$TARGET:$PORT" -cipher "EXPORT" 2>&1)
if echo "$logjam_result" | grep -qi "Cipher|done|handshake"; then
    warn "  Logjam: Export ciphers accepted"
    json_add_vuln "Logjam (Export Ciphers)" "HIGH" 7.5 "Server accepts export-grade DH — vulnerable to Logjam"
    ((VULN_COUNT++))
fi

# Criminal (CRIME)
log "  Checking CRIME..."
crime_check=$(curl -s --max-time 10 -H "Accept-Encoding: br,deflate,gzip" -H "Accept: text/html" "https://$TARGET:$PORT" 2>/dev/null || echo "")
if echo "$crime_check" | grep -qi "zip\|deflate\|compress\|br"; then
    warn "  CRIME: compression detected"
    json_add_vuln "CRIME (TLS Compression)" "MEDIUM" 6.0 "TLS compression enabled — vulnerable to CRIME/BREACH"
    ((VULN_COUNT++))
fi

# OCSP Stapling
log "  Checking OCSP Stapling..."
ocsp_result=$(echo "" | openshift s_client -connect "$TARGET:$PORT" -status 2>&1 | grep -qi "OCSP" && echo "ENABLED" || echo "DISABLED" || true)
if [[ "$ocsp_result" != "ENABLED" ]]; then
    warn "  OCSP stapling: not enabled"
fi

# HSTS header
log "  Checking HSTS..."
hsts_header=$(echo "" | openssl s_client -connect "$TARGET:$PORT" -servername "$TARGET" 2>&1 | grep -i "strict-transport" || echo "")
if [[ -n "$hsts_header" ]]; then
    found "  HSTS: enabled"
else
    warn "  HSTS: not enabled — no force-HTTPS header"
    json_add_vuln "Missing HSTS Header" "LOW" 3.1 "No Strict-Transport-Security header — HTTP available"
fi

# ═══════════════════════════════════════════════════════════
# PHASE 5: Client simulation (common browser ciphers)
# ═══════════════════════════════════════════════════════════
log "Phase 5: Browser cipher compatibility"

browser_ciphers=(
    "ECDHE-RSA-AES128-GCM-SHA256"
    "ECDHE-RSA-AES256-GCM-SHA384"
    "ECDHE-RSA-CHACHA20-POLY1305"
    "AES128-GCM-SHA256"
    "AES256-GCM-SHA384"
)

COMPAT_COUNT=0
for cipher in "${browser_ciphers[@]}"; do
    result=$(echo "" | openssl s_client -connect "$TARGET:$PORT" -cipher "$cipher" 2>&1 | grep -qi "Cipher is|done|SSL-Session" && echo "OK" || echo "FAIL")
    [[ "$result" == "OK" ]] && ((COMPAT_COUNT++))
done

log "  Modern browser compatibility: $COMPAT_COUNT/${#browser_ciphers[@]} ciphers"

# ═══════════════════════════════════════════════════════════
# JSON Summary
# ═══════════════════════════════════════════════════════════
if [[ "$JSON_OUTPUT" == "true" ]]; then
    log "Generating JSON output..."

    # Build protocols JSON
    proto_json="{"
    for p in "${PROTOCOLS_SUPPORTED[@]}"; do
        proto_json+="\"$p\": true, "
    done
    proto_json="${proto_json%, } }"

    # Write full JSON
    {
        echo "{"
        echo "  \"target\": \"$TARGET\","
        echo "  \"port\": $PORT,"
        echo "  \"timestamp\": \"$(date -I)\","
        echo "  \"summary\": {"
        echo "    \"protocols_count\": ${#PROTOCOLS_SUPPORTED[@]},"
        echo "    \"ciphers_count\": $CIPHER_COUNT,"
        echo "    \"weak_ciphers\": $WEAK_CIPHERS,"
        echo "    \"vulnerabilities_found\": $VULN_COUNT,"
        echo "    \"browser_compatibility\": $COMPAT_COUNT"
        echo "  },"
        echo "  \"protocols\": $proto_json,"
        echo "  \"certificate\": {"
        echo "    \"subject\": \"$(echo $subject | tr -d '\n')\","
        echo "    \"issuer\": \"$(echo $issuer | tr -d '\n')\","
        echo "    \"valid_until\": \"$not_after\","
        echo "    \"days_remaining\": $days_left,"
        echo "    \"self_signed\": $(echo "$subject" | grep -q "$issuer" && echo "true" || echo "false")"
        echo "  },"
        echo "  \"vulnerabilities\": ["
        jq -r '.vulnerabilities[] | "    {\"name\": \"\(.name)\", \"severity\": \"\(.severity)\", \"cvss\": \(.cvss)}"' "$JSON_FILE" 2>/dev/null || echo ""
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"
fi

# ═══════════════════════════════════════════════════════════
# Final Report
# ═══════════════════════════════════════════════════════════
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "SSL/TLS Audit Complete — $TARGET:$PORT"
echo -e "${GREEN}[✓]${NC} Protocols:      ${#PROTOCOLS_SUPPORTED[@]} enabled"
echo -e "${GREEN}[✓]${NC} Ciphers:       $CIPHER_COUNT total, $WEAK_CIPHERS weak"
echo -e "${YELLOW}[!]${NC} Vulnerabilities: $VULN_COUNT found"
echo ""
echo -e "  Certificate: ${CYAN}$CERT_FILE${NC}"
echo -e "  Protocols:   ${CYAN}$PROTO_FILE${NC}"
echo -e "  Ciphers:    ${CYAN}$CIPHER_FILE${NC}"
echo -e "  Vulnerabilities: ${RED}$VULN_FILE${NC}"
[[ "$JSON_OUTPUT" == "true" ]] && echo -e "  JSON:       ${BLUE}$JSON_FILE${NC}"
echo ""
log "Audit complete — use only with authorization"