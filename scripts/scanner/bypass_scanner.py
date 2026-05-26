#!/usr/bin/env python3
"""
bypass_scanner.py - Measured 3-phase firewall bypass workflow
=============================================================
Lab-oriented reproduction of the paper workflow:
  Phase 1: Identify
  Phase 2: Probe
  Phase 3: Validate

The script is host-friendly: if it is launched outside the attacker
container, it re-executes itself inside that container so designated
source ports 80/tcp and 53/udp can be bound without extra setup.
"""

import argparse
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, List, Sequence, Tuple

ATTACKER_CONTAINER = "attacker"
CONTAINER_SCRIPT = "/lab/scripts/scanner/bypass_scanner.py"
DEFAULT_TARGET = "172.20.2.2"
HIGH_SOURCE_PORTS = [45123, 52847, 61204]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ServiceSpec:
    name: str
    port: int
    protocol: str
    designated_source_port: int
    probe_payload: bytes
    read_first: bool


@dataclass
class Attempt:
    success: bool
    response_summary: str = ""
    latency_ms: float = 0.0
    error: str = ""


@dataclass
class ServiceResult:
    host: str
    service: str
    port: int
    protocol: str
    designated_source_port: int
    exposure: str = "closed"
    identify_responsive: bool = False
    probe_ok: bool = False
    probe_summary: str = ""
    validated_from_high_port: bool = False
    errors: List[str] = field(default_factory=list)
    security_risks: List[str] = field(default_factory=list)


SERVICE_RISKS: Dict[Tuple[str, int], List[str]] = {
    ("tcp", 22): ["SSH service reachable behind misconfigured firewall"],
    ("tcp", 27017): ["MongoDB internal service exposed through firewall bypass"],
    ("tcp", 3389): ["RDP internal service exposed through firewall bypass"],
    ("udp", 123): ["NTP internal service exposed through UDP source-port bypass"],
}


def build_service_specs() -> List[ServiceSpec]:
    return [
        ServiceSpec("ssh", 22, "tcp", 80, b"", True),
        ServiceSpec("http", 80, "tcp", 80, b"HEAD / HTTP/1.0\r\nHost: victim\r\n\r\n", False),
        ServiceSpec("mongodb", 27017, "tcp", 80, b"", True),
        ServiceSpec("rdp", 3389, "tcp", 80, b"", True),
        ServiceSpec("dns", 53, "udp", 53, b"DNS-LAB-PROBE", False),
        ServiceSpec("ntp", 123, "udp", 53, b"NTP-LAB-PROBE", False),
    ]


def summarize_payload(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return data.hex()[:200]


def _bind_socket(sock: socket.socket, source_port: int) -> str:
    try:
        sock.bind(("", source_port))
        return ""
    except OSError as exc:
        return f"bind to source port {source_port} failed: {exc}"


def _configure_fast_close(sock: socket.socket) -> None:
    linger = struct.pack("ii", 1, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)


def tcp_connect(host: str, port: int, source_port: int, timeout: float = 2.0) -> Attempt:
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _configure_fast_close(sock)
    bind_error = _bind_socket(sock, source_port)
    if bind_error:
        sock.close()
        return Attempt(False, error=bind_error)

    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        return Attempt(True, latency_ms=round((time.time() - start) * 1000, 2))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return Attempt(False, error=str(exc))
    finally:
        sock.close()


def _recv_once(sock: socket.socket) -> bytes:
    try:
        return sock.recv(512)
    except socket.timeout:
        return b""


def tcp_probe(spec: ServiceSpec, host: str, source_port: int, timeout: float = 2.0) -> Attempt:
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _configure_fast_close(sock)
    bind_error = _bind_socket(sock, source_port)
    if bind_error:
        sock.close()
        return Attempt(False, error=bind_error)

    try:
        sock.settimeout(timeout)
        sock.connect((host, spec.port))
        data = b""
        if spec.read_first:
            data = _recv_once(sock)
        if spec.probe_payload:
            sock.sendall(spec.probe_payload)
        if not data:
            data = _recv_once(sock)
        return Attempt(
            True,
            response_summary=summarize_payload(data),
            latency_ms=round((time.time() - start) * 1000, 2),
        )
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return Attempt(False, error=str(exc))
    finally:
        sock.close()


def udp_exchange(host: str, port: int, source_port: int, payload: bytes, timeout: float = 2.0) -> Attempt:
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_error = _bind_socket(sock, source_port)
    if bind_error:
        sock.close()
        return Attempt(False, error=bind_error)

    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(512)
        return Attempt(
            True,
            response_summary=summarize_payload(data),
            latency_ms=round((time.time() - start) * 1000, 2),
        )
    except (socket.timeout, OSError) as exc:
        return Attempt(False, error=str(exc))
    finally:
        sock.close()


class FirewallBypassScanner:
    def __init__(self, target_host: str, max_iterations: int) -> None:
        self.target_host = target_host
        self.max_iterations = max_iterations
        self.service_specs = build_service_specs()

    def run(self) -> Dict:
        previous_state: List[Tuple[str, str, bool, bool]] = []
        final_results: List[ServiceResult] = []
        iterations_run = 0

        for iteration in range(1, self.max_iterations + 1):
            results = [self._scan_service(spec) for spec in self.service_specs]
            state = [
                (result.service, result.exposure, result.probe_ok, result.validated_from_high_port)
                for result in results
            ]
            final_results = results
            iterations_run = iteration
            if iteration > 1 and state == previous_state:
                break
            previous_state = state

        return self._build_report(final_results, iterations_run)

    def _scan_service(self, spec: ServiceSpec) -> ServiceResult:
        result = ServiceResult(
            host=self.target_host,
            service=spec.name,
            port=spec.port,
            protocol=spec.protocol,
            designated_source_port=spec.designated_source_port,
        )

        designated_attempt = self._designated_probe(spec)
        if designated_attempt.error.startswith("bind to source port"):
            result.exposure = "inconclusive"
            result.errors.append(designated_attempt.error)
            return result
        if not designated_attempt.success:
            if designated_attempt.error:
                result.errors.append(designated_attempt.error)
            return result

        result.identify_responsive = True
        result.probe_ok = True
        result.probe_summary = designated_attempt.response_summary

        validation_success = False
        for high_port in HIGH_SOURCE_PORTS:
            attempt = self._validate(spec, high_port)
            if attempt.success:
                validation_success = True
                break

        result.validated_from_high_port = validation_success
        if validation_success:
            result.exposure = "public"
        else:
            result.exposure = "affected"
            result.security_risks = SERVICE_RISKS.get((spec.protocol, spec.port), [])

        return result

    def _designated_probe(self, spec: ServiceSpec) -> Attempt:
        if spec.protocol == "tcp":
            return tcp_probe(spec, self.target_host, spec.designated_source_port)
        return udp_exchange(self.target_host, spec.port, spec.designated_source_port, spec.probe_payload)

    def _validate(self, spec: ServiceSpec, high_port: int) -> Attempt:
        if spec.protocol == "tcp":
            return tcp_connect(self.target_host, spec.port, high_port)
        return udp_exchange(self.target_host, spec.port, high_port, spec.probe_payload)

    def _build_report(self, results: Sequence[ServiceResult], iterations_run: int) -> Dict:
        affected = [item for item in results if item.exposure == "affected"]
        public = [item for item in results if item.exposure == "public"]
        closed = [item for item in results if item.exposure == "closed"]
        inconclusive = [item for item in results if item.exposure == "inconclusive"]

        report = {
            "generated_at": datetime.now().isoformat(),
            "execution_context": {
                "inside_attacker_container": os.environ.get("BYPASS_SCANNER_IN_CONTAINER") == "1",
                "target_host": self.target_host,
            },
            "workflow": {
                "designated_ports": {"tcp": 80, "udp": 53},
                "high_source_ports": HIGH_SOURCE_PORTS,
                "max_iterations": self.max_iterations,
                "iterations_run": iterations_run,
            },
            "phase_stats": {
                "identify_candidates": sum(1 for item in results if item.identify_responsive),
                "probe_successes": sum(1 for item in results if item.probe_ok),
                "validate_public_hits": sum(1 for item in results if item.validated_from_high_port),
            },
            "summary": {
                "public_services": len(public),
                "affected_services": len(affected),
                "closed_services": len(closed),
                "inconclusive_services": len(inconclusive),
                "observable_expansion_pct": round((len(affected) / len(public) * 100) if public else 0.0, 2),
            },
            "services": [asdict(item) for item in results],
            "all_risks": [risk for item in affected for risk in item.security_risks],
        }
        return report


def save_results(report: Dict) -> str:
    out_path = os.path.join(os.path.dirname(__file__), "..", "results", "scan_results.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    return out_path


def print_summary(report: Dict) -> None:
    summary = report["summary"]
    print("\n" + "═" * 60)
    print("SCAN SUMMARY")
    print("═" * 60)
    print(f"  Public services       : {summary['public_services']}")
    print(f"  Affected services     : {summary['affected_services']}")
    print(f"  Closed services       : {summary['closed_services']}")
    print(f"  Inconclusive services : {summary['inconclusive_services']}")
    print(f"  Observable expansion  : {summary['observable_expansion_pct']}%")
    print()

    for item in report["services"]:
        print(
            f"  {item['service']:<8} {item['port']:>5}/{item['protocol']:<3} "
            f"-> {item['exposure']}"
        )
        if item["probe_summary"]:
            print(f"    Probe: {item['probe_summary']}")
        for error in item["errors"]:
            print(f"    Error: {error}")
        for risk in item["security_risks"]:
            print(f"    Risk : {risk}")


def maybe_reexec_inside_attacker(argv: Sequence[str]) -> None:
    if os.environ.get("BYPASS_SCANNER_IN_CONTAINER") == "1":
        return
    if os.path.abspath(__file__).startswith("/lab/"):
        return

    cmd = [
        "docker",
        "exec",
        "-e",
        "BYPASS_SCANNER_IN_CONTAINER=1",
        ATTACKER_CONTAINER,
        "python3",
        CONTAINER_SCRIPT,
        *argv,
    ]
    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.stdout:
        sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    raise SystemExit(completed.returncode)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Measured firewall bypass scanner")
    parser.add_argument("--target-host", default=DEFAULT_TARGET, help="Victim IP address inside the lab")
    parser.add_argument("--max-iterations", type=int, default=1, help="Maximum workflow iterations")
    parser.add_argument("--json", action="store_true", help="Print JSON report to stdout")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    maybe_reexec_inside_attacker(sys.argv[1:])

    scanner = FirewallBypassScanner(args.target_host, args.max_iterations)
    report = scanner.run()
    out_path = save_results(report)

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(
            """
╔══════════════════════════════════════════════════════════╗
║  Firewall Bypass Scanner                                 ║
║  Measured 3-phase reproduction workflow                  ║
╚══════════════════════════════════════════════════════════╝
            """.strip()
        )
        print_summary(report)
        print(f"\nResults saved to: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
