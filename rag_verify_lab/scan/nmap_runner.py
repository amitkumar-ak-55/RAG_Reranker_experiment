from __future__ import annotations

import ipaddress
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import socket
from dataclasses import dataclass
from pathlib import Path

from .normalize import FindingData
from ..config import ROOT

PUBLIC_TARGET = "scanme.nmap.org"


@dataclass
class NmapResult:
    findings: list[FindingData]
    hostname: str
    resolved_ip: str
    command: list[str]
    exit_code: int
    xml_path: Path


def is_public_target(target: str) -> bool:
    return target.strip().lower().rstrip(".") == PUBLIC_TARGET


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target {target}: {exc}") from exc


def target_ip(target: str) -> tuple[str, str]:
    if "/" in target:
        return target, target
    return (target, resolve_target(target)) if not _is_ip(target) else (target, target)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_target(target: str) -> str:
    value = target.strip()
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4 or network.prefixlen < 24:
                raise ValueError
        else:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                labels = value.rstrip(".").split(".")
                if not labels or len(value.rstrip(".")) > 253 or any(
                    not label or len(label) > 63 or not label.replace("-", "a").isalnum()
                    or label.startswith("-") or label.endswith("-") for label in labels
                ):
                    raise ValueError
    except ValueError as exc:
        raise ValueError("Target must be a valid IPv4 address, hostname, or /24-/32 IPv4 CIDR") from exc
    return value


def parse_nmap_xml(xml: str) -> list[FindingData]:
    root = ET.fromstring(xml)
    findings: list[FindingData] = []
    for host in root.findall(".//host"):
        addr = host.find("address")
        ip = addr.attrib.get("addr", "") if addr is not None else ""
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is not None and state.attrib.get("state") != "open":
                continue
            service = port.find("service")
            findings.append(FindingData("nmap", ip, int(port.attrib.get("portid", 0)), port.attrib.get("protocol", ""), service.attrib.get("name", "") if service is not None else "", None, service.attrib.get("product", "") if service is not None else "", "", " ".join(filter(None, [service.attrib.get("product", "") if service is not None else "", service.attrib.get("version", "") if service is not None else ""])), {"xml": ET.tostring(host, encoding="unicode")}))
    return findings


def run_nmap(target: str, port_range: str) -> list[FindingData]:
    return run_nmap_result(target, port_range).findings


def run_nmap_result(target: str, port_range: str) -> NmapResult:
    validate_target(target)
    hostname, resolved_ip = target_ip(target)
    output_dir = ROOT / "data" / "scans"
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output_dir, suffix=".xml", delete=False) as handle:
        output = Path(handle.name)
    command = [
        "nmap",
        "-sT",
        "-sV",
        "-T2",
        "-p",
        port_range,
        "-oX",
        str(output),
        target if "/" in target else resolved_ip,
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=600)
    xml = output.read_text(encoding="utf-8") if output.exists() else "<nmaprun />"
    findings = parse_nmap_xml(xml)
    return NmapResult(findings, hostname, resolved_ip, command, completed.returncode, output)
