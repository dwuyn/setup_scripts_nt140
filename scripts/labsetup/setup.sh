#!/bin/bash
# ============================================================
# Firewall Misconfiguration Lab - Setup Script
# Based on: "Beyond the Horizon" (Oakland S&P 2025)
# ============================================================

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)

ATTACKER_CONTAINER="attacker"
FIREWALL_CONTAINER="firewall_node"
VICTIM_CONTAINER="victim"

OUTSIDE_NETWORK="firewall_outside"
INSIDE_NETWORK="firewall_inside"

OUTSIDE_SUBNET="172.20.1.0/24"
INSIDE_SUBNET="172.20.2.0/24"

ATTACKER_IP="172.20.1.2"
FIREWALL_OUTSIDE_IP="172.20.1.254"
FIREWALL_INSIDE_IP="172.20.2.254"
VICTIM_IP="172.20.2.2"

LAB_MOUNT="/lab"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

usage() {
    cat <<EOF
Usage:
  $(basename "$0") up
  $(basename "$0") mode <flawed|flags|secure>
  $(basename "$0") status
  $(basename "$0") down

Defaults:
  - "up" creates the lab and applies flawed rules.
    - HTTP (80/tcp) and DNS (53/udp) stay public in every mode.
  - SSH (22/tcp), MongoDB (27017/tcp), RDP (3389/tcp), Telnet (23/tcp),
    and NTP (123/udp) are the original protected services.
  - MQTT (1883/tcp), CoAP (5683/udp), and Modbus (502/tcp) are IoT
    extension services, also protected.
  - Internal Admin API (8080/tcp) is a new service reachable only via
    --sport 443 source-port bypass (HTTPS trust misconfiguration).
EOF
}

check_prereqs() {
    log "Checking prerequisites..."
    for cmd in docker python3; do
        command -v "$cmd" >/dev/null 2>&1 || {
            err "Missing required command: $cmd"
            exit 1
        }
    done
    docker info >/dev/null 2>&1 || {
        err "Docker daemon is not available"
        exit 1
    }
    log "All prerequisites met."
}

container_running() {
    docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -q '^true$'
}

ensure_running() {
    container_running "$1" || {
        err "Container '$1' is not running. Use '$0 up' first."
        exit 1
    }
}

create_networks() {
    log "Creating isolated Docker networks..."
    docker network rm "${OUTSIDE_NETWORK}" "${INSIDE_NETWORK}" >/dev/null 2>&1 || true
    docker network create --subnet="${OUTSIDE_SUBNET}" --driver bridge "${OUTSIDE_NETWORK}" >/dev/null
    docker network create --subnet="${INSIDE_SUBNET}" --driver bridge "${INSIDE_NETWORK}" >/dev/null
    log "Networks ready: ${OUTSIDE_NETWORK}, ${INSIDE_NETWORK}"
}

start_victim() {
    log "Starting victim container..."
    docker rm -f "${VICTIM_CONTAINER}" >/dev/null 2>&1 || true

    docker run -d --name "${VICTIM_CONTAINER}" \
        --network "${INSIDE_NETWORK}" \
        --ip "${VICTIM_IP}" \
        --cap-add NET_ADMIN \
        ubuntu:22.04 \
        bash -c "
            set -e
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq openssh-server python3 iproute2 > /dev/null

            mkdir -p /run/sshd
            echo 'root:password123' | chpasswd
            sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
            /usr/sbin/sshd -D &

            cat >/tmp/internal_services.py <<'PY'
import socket
import threading
import time

UDP_RESPONSES = {
    53: b'DNS-LAB-OK\n',
    123: b'NTP-LAB-OK\n',
    5683: b'CoAP 1.0 gateway\n',
}

def serve_udp(port: int, response: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    while True:
        _, addr = sock.recvfrom(2048)
        sock.sendto(response, addr)

for port, response in UDP_RESPONSES.items():
    threading.Thread(target=serve_udp, args=(port, response), daemon=True).start()

while True:
    time.sleep(3600)
PY

            echo 'HTTP-200 OK: Public Lab Service' > /tmp/index.html
            python3 /tmp/internal_services.py &
            python3 -c \"
import socket, threading
def handle(client):
    client.sendall(b'MongoDB 4.2.0 (INTERNAL)\\n')
    client.close()
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 27017))
sock.listen(32)
while True:
    client, _ = sock.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
\" >/tmp/mongodb.log 2>&1 &
            python3 -c \"
import socket, threading
def handle(client):
    client.sendall(b'Windows RDP 7.0 EOL\\n')
    client.close()
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 3389))
sock.listen(32)
while True:
    client, _ = sock.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
\" >/tmp/rdp.log 2>&1 &
            python3 -c \"
import socket, threading
def handle(client):
    client.sendall(b'MQTT 3.1.1 broker\\n')
    client.close()
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 1883))
sock.listen(32)
while True:
    client, _ = sock.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
\" >/tmp/mqtt.log 2>&1 &
            python3 -c \"
import socket, threading
def handle(client):
    client.sendall(b'Modbus/TCP 1.0 ICS\\n')
    client.close()
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 502))
sock.listen(32)
while True:
    client, _ = sock.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
\" >/tmp/modbus.log 2>&1 &
            python3 -c \"
import socket, threading
def handle(client):
    client.sendall(b'Telnet 2.0 LAB\\r\\n')
    client.close()
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 23))
sock.listen(32)
while True:
    client, _ = sock.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
\" >/tmp/telnet.log 2>&1 &
            python3 -c \"
import socket, threading
def handle(client):
    client.sendall(b'Internal Admin API v2.0 (CONFIDENTIAL)\\n')
    client.close()
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 8080))
sock.listen(32)
while True:
    client, _ = sock.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
\" >/tmp/api_admin.log 2>&1 &
            python3 -m http.server 80 --directory /tmp >/tmp/http.log 2>&1 &
            exec tail -f /dev/null
        " > /dev/null

    log "Victim ready with SSH, HTTP, MongoDB, RDP, DNS, NTP, MQTT, CoAP, Modbus, Telnet, and Admin API services."
}

wait_for_victim_services() {
    log "Waiting for victim services to start..."
    local expected_tcp=("22" "80" "27017" "3389" "1883" "502" "23" "8080")
    local expected_udp=("53" "123" "5683")
    local timeout_seconds=120
    local attempt=0
    local listeners=""
    local missing=()
    local port

    while (( attempt < timeout_seconds )); do
        if ! container_running "${VICTIM_CONTAINER}"; then
            err "Victim container exited during bootstrap."
            info "Recent victim logs:"
            docker logs "${VICTIM_CONTAINER}" 2>&1 | tail -n 40 || true
            exit 1
        fi

        listeners=$(docker exec "${VICTIM_CONTAINER}" bash -lc "ss -lntu" 2>/dev/null || true)
        missing=()

        for port in "${expected_tcp[@]}"; do
            if ! grep -q ":${port} " <<<"${listeners}"; then
                missing+=("tcp/${port}")
            fi
        done

        for port in "${expected_udp[@]}"; do
            if ! grep -q ":${port} " <<<"${listeners}"; then
                missing+=("udp/${port}")
            fi
        done

        if (( ${#missing[@]} == 0 )); then
            log "Victim services are listening."
            return
        fi

        if (( attempt > 0 && attempt % 10 == 0 )); then
            info "Victim still starting; waiting on: ${missing[*]}"
        fi

        attempt=$((attempt + 1))
        sleep 1
    done

    err "Victim services did not become ready within ${timeout_seconds}s."
    info "Still missing: ${missing[*]}"
    info "Current listeners:"
    docker exec "${VICTIM_CONTAINER}" ss -lntu 2>/dev/null || true
    info "Recent victim logs:"
    docker logs "${VICTIM_CONTAINER}" 2>&1 | tail -n 40 || true
    exit 1
}

start_firewall() {
    log "Starting firewall container..."
    docker rm -f "${FIREWALL_CONTAINER}" >/dev/null 2>&1 || true

    docker run -d --name "${FIREWALL_CONTAINER}" \
        --network "${OUTSIDE_NETWORK}" \
        --ip "${FIREWALL_OUTSIDE_IP}" \
        --cap-add NET_ADMIN \
        --sysctl net.ipv4.ip_forward=1 \
        ubuntu:22.04 \
        bash -c "
            set -e
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq iptables iproute2 conntrack >/dev/null
            exec tail -f /dev/null
        " >/dev/null

    docker network connect --ip "${FIREWALL_INSIDE_IP}" "${INSIDE_NETWORK}" "${FIREWALL_CONTAINER}" >/dev/null

    until docker exec "${FIREWALL_CONTAINER}" bash -c "command -v iptables" >/dev/null 2>&1; do
        sleep 1
    done

    log "Firewall container is ready."
}

start_attacker() {
    log "Starting attacker container..."
    docker rm -f "${ATTACKER_CONTAINER}" >/dev/null 2>&1 || true

    docker run -d --name "${ATTACKER_CONTAINER}" \
        --network "${OUTSIDE_NETWORK}" \
        --ip "${ATTACKER_IP}" \
        --cap-add NET_ADMIN \
        --cap-add NET_BIND_SERVICE \
        -v "${REPO_ROOT}:${LAB_MOUNT}" \
        -w "${LAB_MOUNT}" \
        ubuntu:22.04 \
        bash -c "
            set -e
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq python3 iproute2 >/dev/null
            exec tail -f /dev/null
        " >/dev/null

    log "Attacker ready at ${ATTACKER_IP} with repo mounted at ${LAB_MOUNT}."
}

setup_routes() {
    log "Configuring static routes through firewall..."

    until docker exec "${ATTACKER_CONTAINER}" bash -c "command -v ip" >/dev/null 2>&1; do
        sleep 1
    done

    until docker exec "${VICTIM_CONTAINER}" bash -c "command -v ip" >/dev/null 2>&1; do
        sleep 1
    done

    docker exec "${ATTACKER_CONTAINER}" ip route replace "${INSIDE_SUBNET}" via "${FIREWALL_OUTSIDE_IP}" >/dev/null
    docker exec "${VICTIM_CONTAINER}" ip route replace "${OUTSIDE_SUBNET}" via "${FIREWALL_INSIDE_IP}" >/dev/null

    log "Routes configured."
}

reset_firewall() {
    docker exec "${FIREWALL_CONTAINER}" bash -c "
        conntrack -F >/dev/null 2>&1 || true
        iptables-legacy -F
        iptables-legacy -X
        iptables-legacy -P INPUT ACCEPT
        iptables-legacy -P OUTPUT ACCEPT
        iptables-legacy -P FORWARD DROP
    " >/dev/null
}

apply_flawed_rules() {
    log "Applying flawed stateless rules..."
    reset_firewall
    docker exec "${FIREWALL_CONTAINER}" bash -c "
        iptables-legacy -A FORWARD -s ${INSIDE_SUBNET} -d ${OUTSIDE_SUBNET} -j ACCEPT
        iptables-legacy -A FORWARD -p tcp -d ${VICTIM_IP} --dport 80 -j ACCEPT
        iptables-legacy -A FORWARD -p udp -d ${VICTIM_IP} --dport 53 -j ACCEPT
        iptables-legacy -A FORWARD -p tcp --sport 80  -d ${INSIDE_SUBNET} -j ACCEPT
        iptables-legacy -A FORWARD -p tcp --sport 443 -d ${INSIDE_SUBNET} -j ACCEPT
        iptables-legacy -A FORWARD -p udp --sport 53  -d ${INSIDE_SUBNET} -j ACCEPT
        iptables-legacy -A FORWARD -s ${OUTSIDE_SUBNET} -d ${INSIDE_SUBNET} -j DROP
    " > /dev/null
    warn "Flawed mode active: TCP bypass via --sport 80 and --sport 443; UDP bypass via --sport 53."
}

apply_flags_rules() {
    log "Applying stateless TCP flag-filtered rules..."
    reset_firewall
    docker exec "${FIREWALL_CONTAINER}" bash -c "
        iptables-legacy -A FORWARD -s ${INSIDE_SUBNET} -d ${OUTSIDE_SUBNET} -j ACCEPT
        iptables-legacy -A FORWARD -p tcp -d ${VICTIM_IP} --dport 80 -j ACCEPT
        iptables-legacy -A FORWARD -p udp -d ${VICTIM_IP} --dport 53 -j ACCEPT
        iptables-legacy -A FORWARD -p tcp --sport 80  --tcp-flags SYN,RST,ACK ACK -d ${INSIDE_SUBNET} -j ACCEPT
        iptables-legacy -A FORWARD -p tcp --sport 443 --tcp-flags SYN,RST,ACK ACK -d ${INSIDE_SUBNET} -j ACCEPT
        iptables-legacy -A FORWARD -p udp --sport 53  -d ${INSIDE_SUBNET} -j ACCEPT
        iptables-legacy -A FORWARD -s ${OUTSIDE_SUBNET} -d ${INSIDE_SUBNET} -j DROP
    " > /dev/null
    warn "Flags mode active: TCP bypass (sport 80/443) blocked by ACK filter; UDP sport-53 bypass remains."
}

apply_secure_rules() {
    log "Applying secure stateful rules..."
    reset_firewall
    docker exec "${FIREWALL_CONTAINER}" bash -c "
        iptables-legacy -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables-legacy -A FORWARD -s ${INSIDE_SUBNET} -d ${OUTSIDE_SUBNET} -m state --state NEW -j ACCEPT
        iptables-legacy -A FORWARD -p tcp -d ${VICTIM_IP} --dport 80 -m state --state NEW -j ACCEPT
        iptables-legacy -A FORWARD -p udp -d ${VICTIM_IP} --dport 53 -j ACCEPT
        iptables-legacy -A FORWARD -s ${OUTSIDE_SUBNET} -d ${INSIDE_SUBNET} -j DROP
    " >/dev/null
    log "Secure mode active: only public HTTP/DNS remain reachable inbound."
}

apply_mode() {
    ensure_running "${FIREWALL_CONTAINER}"
    case "${1:-}" in
        flawed) apply_flawed_rules ;;
        flags) apply_flags_rules ;;
        secure) apply_secure_rules ;;
        *)
            err "Unknown mode: ${1:-}"
            usage
            exit 1
            ;;
    esac
}

detect_mode() {
    if ! container_running "${FIREWALL_CONTAINER}"; then
        echo "stopped"
        return
    fi

    local rules
    rules=$(docker exec "${FIREWALL_CONTAINER}" iptables-legacy -S FORWARD 2>/dev/null || true)

    if grep -q -- "--tcp-flags SYN,RST,ACK ACK" <<<"${rules}"; then
        echo "flags"
    elif grep -q -- "--state" <<<"${rules}" && grep -q -- "ESTABLISHED" <<<"${rules}" && grep -q -- "RELATED" <<<"${rules}"; then
        echo "secure"
    elif grep -q -- "--sport 80" <<<"${rules}" && grep -q -- "--sport 443" <<<"${rules}" && grep -q -- "--sport 53" <<<"${rules}"; then
        echo "flawed"
    else
        echo "unknown"
    fi
}

print_summary() {
    local mode
    mode=$(detect_mode)

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "                 LAB ENVIRONMENT READY"
    echo "════════════════════════════════════════════════════════"
    echo ""
    info "Topology:"
    echo "  [attacker:${ATTACKER_IP}] ──── [firewall:${FIREWALL_OUTSIDE_IP}/${FIREWALL_INSIDE_IP}] ──── [victim:${VICTIM_IP}]"
    echo ""
    info "Public baseline services:"
    echo "  HTTP : TCP 80"
    echo "  DNS  : UDP 53"
    echo ""
    info "Protected services for workflow reproduction:"
    echo "  SSH        : TCP 22"
    echo "  MongoDB    : TCP 27017"
    echo "  RDP        : TCP 3389"
    echo "  Telnet     : TCP 23     [expansion: paper comparison]"
    echo "  NTP        : UDP 123"
    echo "  MQTT       : TCP 1883   [IoT]"
    echo "  CoAP       : UDP 5683   [IoT]"
    echo "  Modbus     : TCP 502    [IoT/ICS]"
    echo "  Admin API  : TCP 8080   [expansion: sport-443 bypass vector]"
    echo ""
    info "Current firewall mode: ${mode}"
    echo ""
    info "Useful commands:"
    echo "  python3 scripts/scanner/bypass_scanner.py"
    echo "  python3 scripts/scanner/compare_rules.py"
    echo "  python3 scripts/scanner/firewall_audit.py"
    echo "  bash scripts/labsetup/setup.sh mode secure"
    echo "════════════════════════════════════════════════════════"
}

status() {
    echo "Containers:"
    for name in "${ATTACKER_CONTAINER}" "${FIREWALL_CONTAINER}" "${VICTIM_CONTAINER}"; do
        if container_running "${name}"; then
            echo "  ${name}: running"
        else
            echo "  ${name}: stopped"
        fi
    done
    echo ""
    echo "Firewall mode: $(detect_mode)"
    if container_running "${FIREWALL_CONTAINER}"; then
        echo ""
        echo "FORWARD chain:"
        docker exec "${FIREWALL_CONTAINER}" iptables-legacy -S FORWARD
    fi
}

down() {
    log "Removing lab containers and networks..."
    docker rm -f "${ATTACKER_CONTAINER}" "${FIREWALL_CONTAINER}" "${VICTIM_CONTAINER}" >/dev/null 2>&1 || true
    docker network rm "${OUTSIDE_NETWORK}" "${INSIDE_NETWORK}" >/dev/null 2>&1 || true
    log "Lab removed."
}

up() {
    check_prereqs
    docker rm -f "${ATTACKER_CONTAINER}" "${FIREWALL_CONTAINER}" "${VICTIM_CONTAINER}" >/dev/null 2>&1 || true
    docker network rm "${OUTSIDE_NETWORK}" "${INSIDE_NETWORK}" >/dev/null 2>&1 || true
    create_networks
    start_victim
    wait_for_victim_services
    start_firewall
    start_attacker
    setup_routes
    apply_flawed_rules
    print_summary
}

main() {
    local command="${1:-up}"

    case "${command}" in
        up)
            up
            ;;
        mode)
            check_prereqs
            apply_mode "${2:-}"
            print_summary
            ;;
        status)
            status
            ;;
        down)
            down
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            err "Unknown command: ${command}"
            usage
            exit 1
            ;;
    esac
}

main "$@"
