#!/usr/bin/env python3
"""
firewall_audit.py - Live firewall rule auditor
==============================================
Audits live rules from the lab firewall container by default and falls
back to explicit sample sets only when requested or when live access is
not available.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[0;31m",
    Severity.MEDIUM: "\033[0;33m",
    Severity.LOW: "\033[0;34m",
    Severity.INFO: "\033[0;37m",
}
RESET = "\033[0m"

RISKY_SOURCE_PORTS = {
    80: ("HTTP", Severity.CRITICAL, "HTTP traffic - common stateless TCP misconfiguration"),
    53: ("DNS", Severity.CRITICAL, "DNS traffic - common stateless UDP misconfiguration"),
    443: ("HTTPS", Severity.HIGH, "HTTPS traffic - can expose hidden services"),
    123: ("NTP", Severity.HIGH, "NTP traffic - common UDP loophole"),
    1883: ("MQTT", Severity.HIGH, "MQTT broker - unauthenticated IoT message bus"),
    5683: ("CoAP", Severity.HIGH, "CoAP gateway - IoT protocol over UDP"),
    502: ("Modbus", Severity.CRITICAL, "Modbus/TCP - ICS/SCADA critical infrastructure"),
}

FLAWED_RULES_SAMPLE = """
-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
-A FORWARD -s 172.20.2.0/24 -d 172.20.1.0/24 -j ACCEPT
-A FORWARD -p tcp -d 172.20.2.2 --dport 80 -j ACCEPT
-A FORWARD -p udp -d 172.20.2.2 --dport 53 -j ACCEPT
-A FORWARD -p tcp --sport 80  -d 172.20.2.0/24 -j ACCEPT
-A FORWARD -p tcp --sport 443 -d 172.20.2.0/24 -j ACCEPT
-A FORWARD -p udp --sport 53  -d 172.20.2.0/24 -j ACCEPT
-A FORWARD -s 172.20.1.0/24 -d 172.20.2.0/24 -j DROP
"""

FLAGS_RULES_SAMPLE = """
-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
-A FORWARD -s 172.20.2.0/24 -d 172.20.1.0/24 -j ACCEPT
-A FORWARD -p tcp -d 172.20.2.2 --dport 80 -j ACCEPT
-A FORWARD -p udp -d 172.20.2.2 --dport 53 -j ACCEPT
-A FORWARD -p tcp --sport 80  --tcp-flags SYN,RST,ACK ACK -d 172.20.2.0/24 -j ACCEPT
-A FORWARD -p tcp --sport 443 --tcp-flags SYN,RST,ACK ACK -d 172.20.2.0/24 -j ACCEPT
-A FORWARD -p udp --sport 53  -d 172.20.2.0/24 -j ACCEPT
-A FORWARD -s 172.20.1.0/24 -d 172.20.2.0/24 -j DROP
"""

SECURE_RULES_SAMPLE = """
-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -s 172.20.2.0/24 -d 172.20.1.0/24 -m state --state NEW -j ACCEPT
-A FORWARD -p tcp -d 172.20.2.2 --dport 80 -m state --state NEW -j ACCEPT
-A FORWARD -p udp -d 172.20.2.2 --dport 53 -j ACCEPT
-A FORWARD -s 172.20.1.0/24 -d 172.20.2.0/24 -j DROP
"""


@dataclass
class IptablesRule:
    chain: str
    protocol: Optional[str]
    source: Optional[str]
    destination: Optional[str]
    sport: Optional[int]
    dport: Optional[int]
    flags: Optional[str]
    state: Optional[str]
    target: str
    raw: str


@dataclass
class AuditFinding:
    rule: IptablesRule
    severity: Severity
    title: str
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)


class IptablesParser:
    RE_SPORT = re.compile(r"--sport\s+(\d+)")
    RE_DPORT = re.compile(r"--dport\s+(\d+)")
    RE_PROTO = re.compile(r"-p\s+(\w+)")
    RE_SRC = re.compile(r"-s\s+([\d./]+)")
    RE_DST = re.compile(r"-d\s+([\d./]+)")
    RE_STATE = re.compile(r"--state\s+([\w,]+)")
    RE_FLAGS = re.compile(r"--tcp-flags\s+(\S+\s+\S+)")

    def parse_save_format(self, rules_text: str) -> List[IptablesRule]:
        rules: List[IptablesRule] = []
        for line in rules_text.splitlines():
            line = line.strip()
            if not line or not line.startswith("-A"):
                continue

            parts = line.split()
            chain = parts[1] if len(parts) > 1 else "UNKNOWN"
            target = "UNKNOWN"
            for index, part in enumerate(parts):
                if part == "-j" and index + 1 < len(parts):
                    target = parts[index + 1]

            rules.append(
                IptablesRule(
                    chain=chain,
                    protocol=self._extract(self.RE_PROTO, line),
                    source=self._extract(self.RE_SRC, line),
                    destination=self._extract(self.RE_DST, line),
                    sport=self._extract_int(self.RE_SPORT, line),
                    dport=self._extract_int(self.RE_DPORT, line),
                    flags=self._extract(self.RE_FLAGS, line),
                    state=self._extract(self.RE_STATE, line),
                    target=target,
                    raw=line,
                )
            )
        return rules

    def parse_from_docker(self, container: str) -> List[IptablesRule]:
        try:
            output = subprocess.check_output(
                ["docker", "exec", container, "iptables-legacy", "-S"],
                stderr=subprocess.DEVNULL,
            ).decode()
        except (subprocess.CalledProcessError, FileNotFoundError, PermissionError):
            return []
        return self.parse_save_format(output)

    @staticmethod
    def _extract(pattern: re.Pattern, text: str) -> Optional[str]:
        match = pattern.search(text)
        return match.group(1) if match else None

    def _extract_int(self, pattern: re.Pattern, text: str) -> Optional[int]:
        value = self._extract(pattern, text)
        return int(value) if value else None


class FirewallAuditor:
    def __init__(self, rules: List[IptablesRule]) -> None:
        self.rules = rules
        self.findings: List[AuditFinding] = []

    def audit(self) -> List[AuditFinding]:
        self.findings = []
        self._check_source_port_bypass()
        self._check_missing_tcp_flags()
        self._check_udp_stateless_rules()
        self._check_stateful_tracking()
        return self.findings

    def _check_source_port_bypass(self) -> None:
        for rule in self.rules:
            if rule.target != "ACCEPT" or rule.sport is None:
                continue
            if rule.state and ("ESTABLISHED" in rule.state or "RELATED" in rule.state):
                continue
            if rule.protocol == "tcp" and rule.flags:
                continue

            if rule.sport not in RISKY_SOURCE_PORTS:
                continue

            proto_name, severity, risk_desc = RISKY_SOURCE_PORTS[rule.sport]
            if rule.protocol == "udp":
                secure_rule = (
                    f"iptables -A {rule.chain} -p udp --sport {rule.sport} "
                    f"-m state --state ESTABLISHED -j ACCEPT"
                )
            else:
                secure_rule = (
                    f"iptables -A {rule.chain} -p tcp --sport {rule.sport} "
                    f"--tcp-flags SYN,RST,ACK ACK -m state --state ESTABLISHED,RELATED -j ACCEPT"
                )

            self.findings.append(
                AuditFinding(
                    rule=rule,
                    severity=severity,
                    title=f"Source-port bypass via {proto_name} ({rule.sport})",
                    description=(
                        f"Rule accepts traffic from source port {rule.sport} without state tracking. "
                        f"This allows new inbound flows to mimic {proto_name} responses. Risk: {risk_desc}."
                    ),
                    remediation=(
                        f"REMOVE: {rule.raw}\n"
                        f"ADD:    {secure_rule}"
                    ),
                    references=["paper §3.1", "paper Figure 1c"],
                )
            )

    def _check_missing_tcp_flags(self) -> None:
        for rule in self.rules:
            if rule.target != "ACCEPT" or rule.protocol != "tcp":
                continue
            if rule.state or rule.flags or rule.sport is not None:
                continue
            if rule.dport is None:
                self.findings.append(
                    AuditFinding(
                        rule=rule,
                        severity=Severity.MEDIUM,
                        title="Broad stateless TCP allow rule without ACK filtering",
                        description=(
                            "Rule accepts TCP without state tracking or TCP flag filtering. "
                            "A stateless firewall cannot distinguish inbound SYN packets from replies."
                        ),
                        remediation=(
                            "Prefer stateful rules. If stateless filtering is required, "
                            "restrict reply paths with '--tcp-flags SYN,RST,ACK ACK'."
                        ),
                        references=["paper §10"],
                    )
                )

    def _check_udp_stateless_rules(self) -> None:
        for rule in self.rules:
            if rule.target != "ACCEPT" or rule.protocol != "udp":
                continue
            if rule.state and "ESTABLISHED" in rule.state:
                continue
            if rule.sport not in RISKY_SOURCE_PORTS:
                continue

            proto_name, _, _ = RISKY_SOURCE_PORTS[rule.sport]
            self.findings.append(
                AuditFinding(
                    rule=rule,
                    severity=Severity.HIGH,
                    title=f"Stateless UDP reply rule for {proto_name} ({rule.sport})",
                    description=(
                        f"UDP rule trusts source port {rule.sport} without state tracking. "
                        "Any host can spoof that source port to reach hidden UDP services."
                    ),
                    remediation=(
                        f"REMOVE: {rule.raw}\n"
                        f"ADD:    iptables -A {rule.chain} -p udp --sport {rule.sport} "
                        "-m state --state ESTABLISHED -j ACCEPT"
                    ),
                    references=["paper §10"],
                )
            )

    def _check_stateful_tracking(self) -> None:
        has_stateful = any(
            rule.state and ("ESTABLISHED" in rule.state or "RELATED" in rule.state)
            for rule in self.rules
        )
        if has_stateful or not self.rules:
            return

        self.findings.append(
            AuditFinding(
                rule=self.rules[0],
                severity=Severity.HIGH,
                title="No stateful tracking detected",
                description=(
                    "No rule uses connection state tracking. Purely stateless forwarding "
                    "is prone to source-port bypass behaviour."
                ),
                remediation=(
                    "Add an ESTABLISHED,RELATED rule and use stateful outbound allow rules."
                ),
                references=["paper §10"],
            )
        )


class AuditReporter:
    def __init__(self, findings: List[AuditFinding], rules: List[IptablesRule], source: str) -> None:
        self.findings = findings
        self.rules = rules
        self.source = source

    def print_console(self) -> None:
        print("\n" + "═" * 70)
        print("  FIREWALL AUDIT REPORT")
        print("═" * 70)
        print(f"\n  Source          : {self.source}")
        print(f"  Rules analyzed  : {len(self.rules)}")
        print(f"  Findings        : {len(self.findings)}")

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = sum(1 for finding in self.findings if finding.severity == severity)
            if count:
                color = SEVERITY_COLOR[severity]
                print(f"  {color}{severity.value:8s}{RESET} : {count}")

        for index, finding in enumerate(self.findings, 1):
            color = SEVERITY_COLOR[finding.severity]
            print(f"\n{'─' * 70}")
            print(f"  Finding #{index}: {color}[{finding.severity.value}]{RESET} {finding.title}")
            print(f"{'─' * 70}")
            print(f"  Rule        : {finding.rule.raw}")
            print(f"  Description : {finding.description}")
            print(f"  Remediation : {finding.remediation}")

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "total_rules": len(self.rules),
            "total_findings": len(self.findings),
            "findings": [
                {
                    "severity": finding.severity.value,
                    "title": finding.title,
                    "description": finding.description,
                    "raw_rule": finding.rule.raw,
                    "remediation": finding.remediation,
                    "references": finding.references,
                }
                for finding in self.findings
            ],
            "severity_counts": {
                severity.value: sum(1 for finding in self.findings if finding.severity == severity)
                for severity in Severity
            },
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit firewall rules for source-port bypass issues")
    parser.add_argument("--container", default="firewall_node", help="Docker container name for live audit")
    parser.add_argument(
        "--source",
        choices=["live", "sample-flawed", "sample-flags", "sample-secure"],
        default="live",
        help="Where to load rules from",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON only")
    return parser.parse_args()


def load_rules(args: argparse.Namespace, parser: IptablesParser) -> tuple[List[IptablesRule], str]:
    if args.source == "sample-flawed":
        return parser.parse_save_format(FLAWED_RULES_SAMPLE), "sample_flawed"
    if args.source == "sample-flags":
        return parser.parse_save_format(FLAGS_RULES_SAMPLE), "sample_flags"
    if args.source == "sample-secure":
        return parser.parse_save_format(SECURE_RULES_SAMPLE), "sample_secure"

    live_rules = parser.parse_from_docker(args.container)
    if live_rules:
        return live_rules, "live_docker"

    print("[!] Live Docker rules unavailable, falling back to flawed sample.")
    return parser.parse_save_format(FLAWED_RULES_SAMPLE), "sample_flawed_fallback"


def save_report(report: dict) -> str:
    out_path = os.path.join(os.path.dirname(__file__), "..", "results", "audit_results.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    return out_path


def main() -> int:
    args = parse_args()
    parser = IptablesParser()
    rules, source = load_rules(args, parser)
    findings = FirewallAuditor(rules).audit()
    reporter = AuditReporter(findings, rules, source)
    report = reporter.to_dict()
    out_path = save_report(report)

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        print(
            """
╔══════════════════════════════════════════════════════════╗
║  Firewall Rule Auditor                                   ║
║  Source-port bypass and stateless rule review            ║
╚══════════════════════════════════════════════════════════╝
            """.strip()
        )
        reporter.print_console()
        print(f"\nJSON report saved to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
