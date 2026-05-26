#!/usr/bin/env python3
"""
compare_rules.py - Measured comparison across firewall modes
============================================================
Runs the measured scanner against flawed, flags, and secure modes
and stores a report for the lab dashboard.
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Dict, List, Tuple

SCRIPT_DIR = os.path.dirname(__file__)
SETUP_SCRIPT = os.path.join(SCRIPT_DIR, "..", "labsetup", "setup.sh")
SCANNER_SCRIPT = os.path.join(SCRIPT_DIR, "bypass_scanner.py")

PROTECTED_SET = {("tcp", 22), ("tcp", 27017), ("tcp", 3389), ("udp", 123)}
PUBLIC_BASELINE_SET = {("tcp", 80), ("udp", 53)}
SERVICE_RISK_WEIGHTS = {
    ("tcp", 22): 15.0,
    ("tcp", 27017): 25.0,
    ("tcp", 3389): 20.0,
    ("udp", 123): 10.0,
}

CONFIGS = [
    ("flawed", "Flawed Stateless", "Stateless allow rules with tcp --sport 80 and udp --sport 53 bypasses"),
    ("flags", "Stateless + TCP Flags", "TCP ACK filtering blocks new TCP bypass, UDP source-port bypass remains"),
    ("secure", "Secure Stateful", "State tracking preserves public HTTP/DNS and blocks hidden-service bypass"),
]

PAPER_REFERENCE = {
    "SSH": {"affected": 234984, "public": 25307484, "expansion_pct": 0.93},
    "Telnet": {"affected": 50820, "public": 2504330, "expansion_pct": 2.03},
    "RDP": {"affected": 7931, "public": 3504675, "expansion_pct": 0.23},
    "MongoDB": {"affected": 338, "public": 198470, "expansion_pct": 0.17},
    "DNS": {"affected": 334358, "public": 5287835, "expansion_pct": 6.32},
    "NTP": {"affected": 824389, "public": 6545301, "expansion_pct": 12.60},
}


@dataclass
class ExperimentResult:
    mode: str
    config_name: str
    config_desc: str
    public_services: int
    affected_services: int
    false_positive_candidates: int
    candidate_services: int
    detection_rate: float
    false_positive_rate: float
    observable_expansion_pct: float
    scan_duration_sec: float
    lab_only_risk_score: float
    affected_service_ids: List[str]
    public_service_ids: List[str]


def service_key(service: Dict) -> Tuple[str, int]:
    return (service["protocol"], service["port"])


def service_id(service: Dict) -> str:
    return f"{service['port']}/{service['protocol']}"


def run_command(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def set_mode(mode: str) -> None:
    completed = run_command(["bash", SETUP_SCRIPT, "mode", mode])
    if completed.stdout.strip():
        print(completed.stdout.strip())


def run_scanner() -> Dict:
    completed = run_command([sys.executable, SCANNER_SCRIPT, "--json"])
    return json.loads(completed.stdout)


def summarize_config(mode: str, name: str, desc: str, report: Dict, duration: float) -> ExperimentResult:
    services = report["services"]
    public_services = [service for service in services if service["exposure"] == "public"]
    affected_services = [service for service in services if service["exposure"] == "affected"]
    candidate_services = [
        service for service in services
        if service["identify_responsive"] and service["probe_ok"]
    ]
    false_positives = [service for service in candidate_services if service["exposure"] == "public"]

    risk_score = min(
        100.0,
        sum(SERVICE_RISK_WEIGHTS.get(service_key(service), 0.0) for service in affected_services),
    )

    return ExperimentResult(
        mode=mode,
        config_name=name,
        config_desc=desc,
        public_services=len(public_services),
        affected_services=len(affected_services),
        false_positive_candidates=len(false_positives),
        candidate_services=len(candidate_services),
        detection_rate=round(len(affected_services) / len(PROTECTED_SET), 4),
        false_positive_rate=round(
            len(false_positives) / len(candidate_services), 4
        ) if candidate_services else 0.0,
        observable_expansion_pct=round(
            (len(affected_services) / len(PUBLIC_BASELINE_SET) * 100.0), 2
        ),
        scan_duration_sec=round(duration, 2),
        lab_only_risk_score=round(risk_score, 1),
        affected_service_ids=sorted(service_id(service) for service in affected_services),
        public_service_ids=sorted(service_id(service) for service in public_services),
    )


def generate_report(results: List[ExperimentResult]) -> Dict:
    return {
        "generated_at": datetime.now().isoformat(),
        "provenance": "measured",
        "baseline_public_set": sorted(f"{port}/{proto}" for proto, port in PUBLIC_BASELINE_SET),
        "protected_set": sorted(f"{port}/{proto}" for proto, port in PROTECTED_SET),
        "experiment_configs": [asdict(result) for result in results],
        "paper_reference_data": PAPER_REFERENCE,
        "metrics_explanation": {
            "detection_rate": "affected protected services / total protected services in the lab",
            "false_positive_rate": "public services seen during identify+probe / all identify+probe candidates",
            "observable_expansion_pct": "affected services / public baseline services * 100",
            "lab_only_risk_score": "lab-specific weighted score over affected services",
        },
    }


def save_report(report: Dict) -> str:
    out_path = os.path.join(SCRIPT_DIR, "..", "results", "comparison_results.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    return out_path


def print_table(results: List[ExperimentResult]) -> None:
    print("\n" + "═" * 92)
    print(f"{'Config':<24} {'Affected':>8} {'Public':>8} {'Det.Rate':>10} {'FP Rate':>9} {'Expansion':>11} {'Risk':>7}")
    print("─" * 92)
    for result in results:
        print(
            f"{result.config_name:<24} "
            f"{result.affected_services:>8} "
            f"{result.public_services:>8} "
            f"{result.detection_rate * 100:>9.1f}% "
            f"{result.false_positive_rate * 100:>8.1f}% "
            f"{result.observable_expansion_pct:>10.1f}% "
            f"{result.lab_only_risk_score:>6.1f}"
        )
    print("═" * 92)


def main() -> int:
    print(
        """
╔══════════════════════════════════════════════════════════╗
║  Firewall Config Comparison                              ║
║  Measured workflow across flawed, flags, secure modes    ║
╚══════════════════════════════════════════════════════════╝
        """.strip()
    )

    results: List[ExperimentResult] = []

    for mode, name, desc in CONFIGS:
        print(f"\n[+] Switching to mode: {mode}")
        set_mode(mode)
        time.sleep(1.0)

        start = time.time()
        report = run_scanner()
        duration = time.time() - start
        result = summarize_config(mode, name, desc, report, duration)
        results.append(result)

        print(f"    affected: {result.affected_services}")
        print(f"    public  : {result.public_services}")
        print(f"    ids     : {', '.join(result.affected_service_ids) or 'none'}")

    print_table(results)

    report = generate_report(results)
    out_path = save_report(report)
    print(f"\nMeasured comparison report saved to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
