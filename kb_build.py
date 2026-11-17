#!/usr/bin/env python3
"""
kb_build.py: Build the vulnerability knowledge base for retrieval-augmented security assessment.

Official sources:
1. NVD CVE API 2.0 (NIST)
2. CISA Known Exploited Vulnerabilities (KEV) Catalog
3. MITRE CWE Catalog XML
4. MITRE ATT&CK Enterprise STIX Bundle
5. ProjectDiscovery Nuclei Templates
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
import xml.etree.ElementTree as ET
import zipfile

import requests
import yaml

LICENCE_NVD = "NVD data is in the public domain (US Government Work) - https://nvd.nist.gov/general/terms-of-use"
LICENCE_CISA = "Public domain / US Government Work - https://www.cisa.gov/terms-of-use"
LICENCE_CWE = "MITRE CWE Terms of Use: Copyright (c) MITRE Corporation. Free for use with attribution - https://cwe.mitre.org/about/termsofuse.html"
LICENCE_ATTACK = "MITRE ATT&CK Terms of Use: Creative Commons Attribution 4.0 International (CC BY 4.0) - https://attack.mitre.org/resources/terms-of-use/"
LICENCE_NUCLEI = "MIT License - Copyright (c) ProjectDiscovery, Inc. - https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md"

URL_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
URL_CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URL_CWE_ZIP = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
URL_ATTACK_STIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
URL_NUCLEI_ZIP = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"

RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
RE_CWE = re.compile(r"^CWE-\d+$")
RE_ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")

ALLOWED_SKIPPED_REASONS = [
    "INVALID_ID_FORMAT",
    "CVE_NOT_FOUND_IN_NVD",
    "NVD_REQUEST_FAILED",
    "CWE_NOT_IN_CATALOG",
    "TECHNIQUE_NOT_IN_ATTACK",
    "NVD_CWE_PLACEHOLDER",
    "EMPTY_TEXT_FIELD",
    "UNQUALIFIED_DISTRACTOR",
    "DUPLICATE_DOC_ID",
]

SCHEMA_KEYS = [
    "doc_id",
    "doc_type",
    "title",
    "text",
    "cve_ids",
    "cwe_ids",
    "attack_ids",
    "products",
    "severity",
    "cvss_score",
    "cvss_version",
    "known_exploited",
    "published",
    "last_modified",
    "source",
    "source_url",
    "retrieved_at",
    "licence",
    "group",
]


def load_env_file(env_path: Path) -> dict[str, str]:
    env_vars: dict[str, str] = {}
    if not env_path.is_file():
        return env_vars
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    env_vars[key.strip()] = val.strip().strip("'\"")
    except Exception:
        pass
    return env_vars


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def stream_download(
    url: str,
    dest_path: Path,
    session: requests.Session,
    refresh: bool = False,
    headers: dict[str, str] | None = None,
) -> tuple[str, int, float, str]:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.is_file() and not refresh:
        size_bytes = dest_path.stat().st_size
        sha = compute_sha256(dest_path)
        mtime = datetime.fromtimestamp(dest_path.stat().st_mtime, timezone.utc).isoformat()
        size_mb = size_bytes / (1024 * 1024)
        print(f"[CACHE] {url} -> {dest_path.name} ({size_mb:.2f} MB, sha256={sha[:10]}...)")
        return sha, size_bytes, 0.0, mtime

    print(f"[DOWNLOAD] Streaming {url} to {dest_path.name}...")
    tmp_path = dest_path.with_suffix(".tmp")
    start = time.time()
    h = hashlib.sha256()
    req_headers = {"User-Agent": "CysekRAG-KBBuild/1.0"}
    if headers:
        req_headers.update(headers)

    with session.get(url, headers=req_headers, stream=True, timeout=120) as r:
        r.raise_for_status()
        with open(tmp_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
                    h.update(chunk)

    if dest_path.exists():
        dest_path.unlink()
    tmp_path.rename(dest_path)

    elapsed = time.time() - start
    size_bytes = dest_path.stat().st_size
    size_mb = size_bytes / (1024 * 1024)
    sha = h.hexdigest()
    ts = datetime.now(timezone.utc).isoformat()
    print(f"[DOWNLOAD] Completed {dest_path.name} ({size_mb:.2f} MB in {elapsed:.2f}s, sha256={sha[:10]}...)")
    return sha, size_bytes, elapsed, ts


def read_seed_file(path: Path) -> list[str]:
    if not path.is_file():
        return []
    items: list[str] = []
    seen: set[str] = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line not in seen:
                seen.add(line)
                items.append(line)
    return items


def make_title(doc_id: str, text: str) -> str:
    cleaned = " ".join(text.strip().split())
    sentence = cleaned
    for delim in [". ", ".\n", ".\r\n"]:
        if delim in cleaned:
            sentence = cleaned.split(delim, 1)[0] + "."
            break
    prefix = f"{doc_id}: "
    avail = 120 - len(prefix)
    if avail < 10:
        return f"{prefix}{sentence}"[:120]
    if len(sentence) > avail:
        sentence = sentence[: avail - 3].rstrip() + "..."
    return f"{prefix}{sentence}"


def extract_cpe_vendor_product(cpe_str: str) -> tuple[str, str] | None:
    parts = cpe_str.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor = parts[3].strip().lower()
        product = parts[4].strip().lower()
        if vendor and product and vendor != "*" and product != "*":
            return vendor, product
    return None


def fetch_nvd_cve(
    cve_id: str,
    nvd_cache_dir: Path,
    session: requests.Session,
    nvd_api_key: str,
    nvd_delay: float,
    last_req_time: float,
    refresh: bool = False,
) -> tuple[dict[str, Any] | None, int, float, str]:
    cve_cache_path = nvd_cache_dir / f"{cve_id}.json"
    cve_data = None

    if cve_cache_path.is_file() and not refresh:
        try:
            with open(cve_cache_path, "r", encoding="utf-8") as f:
                cve_data = json.load(f)
            sha = compute_sha256(cve_cache_path)
            return cve_data, 200, last_req_time, sha
        except Exception:
            cve_data = None

    now_t = time.time()
    elapsed_since_last = now_t - last_req_time
    if elapsed_since_last < nvd_delay:
        time.sleep(nvd_delay - elapsed_since_last)

    headers = {}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    retries = 3
    status = 0
    while retries > 0:
        try:
            last_req_time = time.time()
            resp = session.get(URL_NVD_API, params={"cveId": cve_id}, headers=headers, timeout=60)
            status = resp.status_code
            if status == 200:
                cve_data = resp.json()
                with open(cve_cache_path, "w", encoding="utf-8") as f:
                    json.dump(cve_data, f)
                break
            elif status in (403, 429, 503):
                time.sleep(10.0)
                retries -= 1
            else:
                break
        except Exception:
            retries -= 1
            time.sleep(10.0)

    sha = compute_sha256(cve_cache_path) if cve_cache_path.is_file() else ""
    return cve_data, status, last_req_time, sha


def parse_nvd_record(cve_id: str, cve_data: dict[str, Any]) -> dict[str, Any] | None:
    vulns = cve_data.get("vulnerabilities", [])
    if not vulns or "cve" not in vulns[0]:
        return None

    cve_obj = vulns[0]["cve"]
    actual_id = cve_obj.get("id", "").strip().upper()
    if actual_id != cve_id:
        return None

    descriptions = cve_obj.get("descriptions", [])
    raw_en_desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            raw_en_desc = d.get("value", "")
            break

    cwe_tokens: list[str] = []
    catalog_cwes: list[str] = []
    weaknesses = cve_obj.get("weaknesses", [])
    for w in weaknesses:
        for w_desc in w.get("description", []):
            val = w_desc.get("value", "").strip()
            if not val:
                continue
            cwe_tokens.append(val)
            if RE_CWE.match(val):
                catalog_cwes.append(val)

    products: list[str] = []
    cpe_vendor_products: set[tuple[str, str]] = set()
    configs = cve_obj.get("configurations", [])
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                crit = match.get("criteria")
                if crit and crit not in products:
                    products.append(crit)
                    vp = extract_cpe_vendor_product(crit)
                    if vp:
                        cpe_vendor_products.add(vp)

    severity: str | None = None
    cvss_score: float | None = None
    cvss_version: str | None = None
    metrics = cve_obj.get("metrics", {})

    if metrics.get("cvssMetricV31"):
        m = metrics["cvssMetricV31"][0]
        cvss_data = m.get("cvssData", {})
        score_val = cvss_data.get("baseScore")
        cvss_score = float(score_val) if score_val is not None else None
        severity = cvss_data.get("baseSeverity")
        cvss_version = "3.1"
    elif metrics.get("cvssMetricV30"):
        m = metrics["cvssMetricV30"][0]
        cvss_data = m.get("cvssData", {})
        score_val = cvss_data.get("baseScore")
        cvss_score = float(score_val) if score_val is not None else None
        severity = cvss_data.get("baseSeverity")
        cvss_version = "3.0"
    elif metrics.get("cvssMetricV2"):
        m = metrics["cvssMetricV2"][0]
        cvss_data = m.get("cvssData", {})
        score_val = cvss_data.get("baseScore")
        cvss_score = float(score_val) if score_val is not None else None
        severity = cvss_data.get("baseSeverity")
        cvss_version = "2.0"

    if severity:
        severity = str(severity).upper()

    return {
        "id": cve_id,
        "text": raw_en_desc,
        "cwe_tokens": cwe_tokens,
        "catalog_cwes": catalog_cwes,
        "products": products,
        "cpe_vendor_products": cpe_vendor_products,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "published": cve_obj.get("published"),
        "last_modified": cve_obj.get("lastModified"),
    }


def qualify_distractor(
    cand_cwes: set[str],
    cand_vps: set[tuple[str, str]],
    target_cwe_set: set[str],
    target_vp_set: set[tuple[str, str]],
) -> dict[str, Any] | None:
    """
    Qualify a distractor candidate against target CVEs:
    a. catalog CWE ID in common -> rule "cwe"
    b. (vendor, product) pair in common -> rule "vendor_product" (vendor alone is never enough)
    If both rules match, record "cwe" first and list the other match under "also".
    """
    common_cwes = cand_cwes & target_cwe_set
    common_vps = cand_vps & target_vp_set

    if not common_cwes and not common_vps:
        return None

    if common_cwes and common_vps:
        matched_cwe = sorted(list(common_cwes))[0]
        matched_vp = sorted(list(common_vps))[0]
        return {
            "rule": "cwe",
            "value": matched_cwe,
            "also": {
                "rule": "vendor_product",
                "value": f"{matched_vp[0]}:{matched_vp[1]}",
            },
        }
    elif common_cwes:
        matched_cwe = sorted(list(common_cwes))[0]
        return {
            "rule": "cwe",
            "value": matched_cwe,
        }
    else:
        matched_vp = sorted(list(common_vps))[0]
        return {
            "rule": "vendor_product",
            "value": f"{matched_vp[0]}:{matched_vp[1]}",
        }


def parse_attack_bundle(bundle: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], set[tuple[str, str]]]:
    """
    Parses enterprise-attack STIX bundle.
    Returns:
    - attack_patterns: mapping technique_id -> attack-pattern STIX object
    - explicit_cwe_rels: set of (technique_id, cwe_id) explicit relationships
    """
    attack_patterns: dict[str, dict[str, Any]] = {}
    stix_id_to_tech: dict[str, str] = {}
    explicit_cwe_rels: set[tuple[str, str]] = set()

    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                    t_id = ref["external_id"].strip().upper()
                    is_inactive = obj.get("revoked", False) or obj.get("x_mitre_deprecated", False)
                    if t_id not in attack_patterns or not is_inactive:
                        attack_patterns[t_id] = obj
                    stix_id_to_tech[obj.get("id", "")] = t_id

            t_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                    t_id = ref["external_id"].strip().upper()
                    break
            if t_id:
                for ref in obj.get("external_references", []):
                    ext_id = ref.get("external_id", "").strip().upper()
                    if RE_CWE.match(ext_id):
                        explicit_cwe_rels.add((t_id, ext_id))
                    elif ref.get("source_name", "").upper() == "CWE" and ext_id:
                        cwe_id = ext_id if ext_id.startswith("CWE-") else f"CWE-{ext_id}"
                        if RE_CWE.match(cwe_id):
                            explicit_cwe_rels.add((t_id, cwe_id))

    for obj in bundle.get("objects", []):
        if obj.get("type") == "relationship":
            src_ref = obj.get("source_ref", "")
            tgt_ref = obj.get("target_ref", "")
            t_id = stix_id_to_tech.get(src_ref) or stix_id_to_tech.get(tgt_ref)
            if t_id:
                other_ref = tgt_ref if stix_id_to_tech.get(src_ref) else src_ref
                m = re.search(r"CWE-\d+", other_ref, re.IGNORECASE)
                if m:
                    explicit_cwe_rels.add((t_id, m.group(0).upper()))
                for ref in obj.get("external_references", []):
                    ext_id = ref.get("external_id", "").strip().upper()
                    if RE_CWE.match(ext_id):
                        explicit_cwe_rels.add((t_id, ext_id))

    return attack_patterns, explicit_cwe_rels


def process_attack_candidate(
    tech_id: str,
    attack_patterns: dict[str, dict[str, Any]],
    attack_ts: str,
) -> tuple[dict[str, Any] | None, tuple[str, str] | None]:
    """
    Validates and builds an ATT&CK technique record from the STIX catalog.
    Returns (record, None) or (None, (reason, detail)).
    """
    if not RE_ATTACK.match(tech_id):
        return None, ("INVALID_ID_FORMAT", "ID does not match TNNNN[.NNN]")

    if tech_id not in attack_patterns:
        return None, ("TECHNIQUE_NOT_IN_ATTACK", "Technique ID not found in Enterprise bundle")

    obj = attack_patterns[tech_id]
    if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
        return None, ("TECHNIQUE_NOT_IN_ATTACK", "deprecated or revoked")

    desc = obj.get("description", "")
    if not desc or not desc.strip():
        return None, ("EMPTY_TEXT_FIELD", "No description in STIX object")

    name = obj.get("name", "").strip()
    title = f"{tech_id}: {name}"

    raw_ds = obj.get("x_mitre_data_sources")
    if raw_ds is not None:
        cwe_ids = list(raw_ds) if isinstance(raw_ds, list) else [str(raw_ds)]
    else:
        cwe_ids = []

    source_url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            source_url = ref["url"]
            break

    rec = make_record(
        doc_id=tech_id,
        doc_type="attack",
        title=title,
        text=desc,
        cve_ids=[],
        cwe_ids=cwe_ids,
        attack_ids=[tech_id],
        products=[],
        severity=None,
        cvss_score=None,
        cvss_version=None,
        known_exploited=None,
        published=obj.get("created"),
        last_modified=obj.get("modified"),
        source="MITRE ATT&CK",
        source_url=source_url,
        retrieved_at=attack_ts,
        licence=LICENCE_ATTACK,
        group="positive",
    )
    return rec, None


def make_record(
    doc_id: str,
    doc_type: str,
    title: str,
    text: str,
    cve_ids: list[str],
    cwe_ids: list[str],
    attack_ids: list[str],
    products: list[str],
    severity: str | None,
    cvss_score: float | None,
    cvss_version: str | None,
    known_exploited: bool | None,
    published: str | None,
    last_modified: str | None,
    source: str,
    source_url: str,
    retrieved_at: str,
    licence: str,
    group: str,
) -> dict[str, Any]:
    return {
        "doc_id": doc_id,
        "doc_type": doc_type,
        "title": title,
        "text": text,
        "cve_ids": cve_ids,
        "cwe_ids": cwe_ids,
        "attack_ids": attack_ids,
        "products": products,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "known_exploited": known_exploited,
        "published": published,
        "last_modified": last_modified,
        "source": source,
        "source_url": source_url,
        "retrieved_at": retrieved_at,
        "licence": licence,
        "group": group,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build security assessment vulnerability knowledge base.")
    parser.add_argument("--refresh", action="store_true", help="Force fresh downloads instead of reusing cache.")
    parser.add_argument("--seed-cves", default="data/kb_seed_cves.txt", help="Path to seed CVE IDs file.")
    parser.add_argument("--seed-distractors", default="data/kb_seed_distractors.txt", help="Path to distractor CVE IDs file.")
    parser.add_argument("--seed-attack", default="data/kb_seed_attack.txt", help="Path to seed ATT&CK technique IDs file.")
    parser.add_argument("--output-dir", default="data/kb", help="Directory where KB output files will be written.")
    parser.add_argument("--cache-dir", default="data/kb_cache", help="Directory where raw source feeds are cached.")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    cache_dir = Path(args.cache_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": "CysekRAG-KBBuild/1.0"})

    env_vars = load_env_file(Path(".env"))
    nvd_api_key = os.getenv("NVD_API_KEY") or env_vars.get("NVD_API_KEY", "").strip()

    seed_cves = read_seed_file(Path(args.seed_cves))
    seed_distractors = read_seed_file(Path(args.seed_distractors))
    seed_attacks = read_seed_file(Path(args.seed_attack))

    skipped_records: list[dict[str, Any]] = []

    def add_skipped(item_id: str, item_type: str, reason: str, details: str = "") -> None:
        if reason not in ALLOWED_SKIPPED_REASONS:
            raise ValueError(f"Unknown skipped reason: {reason}")
        skipped_records.append({
            "id": item_id,
            "type": item_type,
            "reason": reason,
            "details": details,
        })

    # 1. Download and parse CISA KEV
    print("\n[Step 1/5] Downloading CISA KEV catalog...")
    cisa_cache = cache_dir / "known_exploited_vulnerabilities.json"
    cisa_sha, cisa_bytes, cisa_elapsed, cisa_ts = stream_download(
        URL_CISA_KEV, cisa_cache, session, refresh=args.refresh
    )
    with open(cisa_cache, "r", encoding="utf-8") as f:
        cisa_data = json.load(f)
    kev_map: dict[str, dict[str, Any]] = {
        v["cveID"].strip().upper(): v
        for v in cisa_data.get("vulnerabilities", [])
        if "cveID" in v
    }

    # 2. Process Target CVEs
    print(f"\n[Step 2/5] Fetching and processing {len(seed_cves)} target CVEs from NVD...")
    target_cve_docs: list[dict[str, Any]] = []
    referenced_cwe_ids: set[str] = set()
    target_cwe_set: set[str] = set()
    target_vp_set: set[tuple[str, str]] = set()

    nvd_cache_dir = cache_dir / "nvd"
    nvd_cache_dir.mkdir(parents=True, exist_ok=True)
    nvd_delay = 0.6 if nvd_api_key else 6.0
    last_nvd_req_time = 0.0
    nvd_cached_shas: dict[str, str] = {}

    for cve_id in seed_cves:
        cve_id_norm = cve_id.strip().upper()
        if not RE_CVE.match(cve_id_norm):
            add_skipped(cve_id_norm, "cve", "INVALID_ID_FORMAT", "ID does not match CVE-YYYY-NNNN+")
            continue

        cve_data, status, last_nvd_req_time, sha = fetch_nvd_cve(
            cve_id_norm, nvd_cache_dir, session, nvd_api_key, nvd_delay, last_nvd_req_time, refresh=args.refresh
        )
        if sha:
            nvd_cached_shas[cve_id_norm] = sha

        if status != 200 or not cve_data:
            add_skipped(cve_id_norm, "cve", "CVE_NOT_FOUND_IN_NVD" if status == 404 else "NVD_REQUEST_FAILED", f"HTTP {status}")
            continue

        parsed = parse_nvd_record(cve_id_norm, cve_data)
        if not parsed:
            add_skipped(cve_id_norm, "cve", "CVE_NOT_FOUND_IN_NVD", "Payload missing cve object")
            continue

        raw_text = parsed["text"]
        if not raw_text or not raw_text.strip():
            add_skipped(cve_id_norm, "cve", "EMPTY_TEXT_FIELD", "No English description")
            continue

        if not parsed["catalog_cwes"]:
            for token in parsed["cwe_tokens"]:
                if not RE_CWE.match(token):
                    add_skipped(token, "cwe", "NVD_CWE_PLACEHOLDER", f"Placeholder for {cve_id_norm}")

        for cwe_id in parsed["catalog_cwes"]:
            referenced_cwe_ids.add(cwe_id)
            target_cwe_set.add(cwe_id)

        target_vp_set.update(parsed["cpe_vendor_products"])

        is_kev = cve_id_norm in kev_map
        group_val = "kev" if is_kev else "positive"

        rec = make_record(
            doc_id=cve_id_norm,
            doc_type="cve",
            title=make_title(cve_id_norm, raw_text),
            text=raw_text,
            cve_ids=[cve_id_norm],
            cwe_ids=parsed["cwe_tokens"],
            attack_ids=[],
            products=parsed["products"],
            severity=parsed["severity"],
            cvss_score=parsed["cvss_score"],
            cvss_version=parsed["cvss_version"],
            known_exploited=is_kev,
            published=parsed["published"],
            last_modified=parsed["last_modified"],
            source="NVD",
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id_norm}",
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            licence=LICENCE_NVD,
            group=group_val,
        )
        target_cve_docs.append(rec)

    # 3. Process Distractor CVEs
    print(f"\n[Step 3/5] Processing {len(seed_distractors)} candidate distractor CVEs...")
    distractor_cve_docs: list[dict[str, Any]] = []
    distractor_matches: dict[str, dict[str, Any]] = {}
    distractor_cwe_ids: set[str] = set()

    for dist_id in seed_distractors:
        dist_id_norm = dist_id.strip().upper()
        if not RE_CVE.match(dist_id_norm):
            add_skipped(dist_id_norm, "distractor", "INVALID_ID_FORMAT", "ID does not match CVE-YYYY-NNNN+")
            continue

        if dist_id_norm in kev_map:
            add_skipped(dist_id_norm, "distractor", "UNQUALIFIED_DISTRACTOR", "candidate is in CISA KEV")
            continue

        cve_data, status, last_nvd_req_time, sha = fetch_nvd_cve(
            dist_id_norm, nvd_cache_dir, session, nvd_api_key, nvd_delay, last_nvd_req_time, refresh=args.refresh
        )
        if sha:
            nvd_cached_shas[dist_id_norm] = sha

        if status == 404:
            add_skipped(dist_id_norm, "distractor", "CVE_NOT_FOUND_IN_NVD", f"HTTP {status}")
            continue
        elif status != 200 or not cve_data:
            add_skipped(dist_id_norm, "distractor", "NVD_REQUEST_FAILED", f"HTTP {status}")
            continue

        parsed = parse_nvd_record(dist_id_norm, cve_data)
        if not parsed:
            add_skipped(dist_id_norm, "distractor", "CVE_NOT_FOUND_IN_NVD", "Payload missing cve object")
            continue

        raw_text = parsed["text"]
        if not raw_text or not raw_text.strip():
            add_skipped(dist_id_norm, "distractor", "EMPTY_TEXT_FIELD", "No English description")
            continue

        cand_cwes = set(parsed["catalog_cwes"])
        cand_vps = parsed["cpe_vendor_products"]
        match_info = qualify_distractor(cand_cwes, cand_vps, target_cwe_set, target_vp_set)
        if not match_info:
            add_skipped(dist_id_norm, "distractor", "UNQUALIFIED_DISTRACTOR", "no shared CWE or (vendor, product) with targets")
            continue

        distractor_matches[dist_id_norm] = match_info

        for cwe_id in parsed["catalog_cwes"]:
            referenced_cwe_ids.add(cwe_id)
            distractor_cwe_ids.add(cwe_id)

        rec = make_record(
            doc_id=dist_id_norm,
            doc_type="distractor",
            title=make_title(dist_id_norm, raw_text),
            text=raw_text,
            cve_ids=[dist_id_norm],
            cwe_ids=parsed["cwe_tokens"],
            attack_ids=[],
            products=parsed["products"],
            severity=parsed["severity"],
            cvss_score=parsed["cvss_score"],
            cvss_version=parsed["cvss_version"],
            known_exploited=False,
            published=parsed["published"],
            last_modified=parsed["last_modified"],
            source="NVD",
            source_url=f"https://nvd.nist.gov/vuln/detail/{dist_id_norm}",
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            licence=LICENCE_NVD,
            group="distractor",
        )
        distractor_cve_docs.append(rec)

    # 4. MITRE CWE Catalog XML
    print("\n[Step 4/5] Downloading and parsing MITRE CWE XML catalog...")
    cwe_zip_path = cache_dir / "cwec_latest.xml.zip"
    cwe_sha, cwe_bytes, cwe_elapsed, cwe_ts = stream_download(
        URL_CWE_ZIP, cwe_zip_path, session, refresh=args.refresh
    )

    cwe_catalog: dict[str, dict[str, str]] = {}
    cwe_explicit_attack_refs: dict[str, set[str]] = {}
    catalog_version = "unknown"
    with zipfile.ZipFile(cwe_zip_path, "r") as z:
        xml_filenames = [n for n in z.namelist() if n.lower().endswith(".xml")]
        if not xml_filenames:
            print("[ERROR] No XML found inside CWE catalog zip.")
        else:
            with z.open(xml_filenames[0]) as xml_file:
                for event, elem in ET.iterparse(xml_file, events=("start", "end")):
                    tag = elem.tag.split("}")[-1]
                    if event == "start" and tag == "Weakness_Catalog":
                        catalog_version = elem.get("Version") or elem.get("Catalog_Version") or "latest"
                    elif event == "end" and tag == "Weakness":
                        w_id = elem.get("ID", "").strip()
                        w_name = elem.get("Name", "").strip()
                        desc_text = ""
                        for child in elem:
                            child_tag = child.tag.split("}")[-1]
                            if child_tag == "Description" and child.text:
                                desc_text = child.text
                                break
                        if w_id and w_name:
                            cwe_key = f"CWE-{w_id}"
                            cwe_catalog[cwe_key] = {
                                "name": w_name,
                                "description": desc_text,
                            }
                            for child in elem.iter():
                                ctag = child.tag.split("}")[-1]
                                if "Taxonomy_Mapping" in ctag and ("ATT&CK" in child.get("Taxonomy_Name", "") or "ATTACK" in child.get("Taxonomy_Name", "")):
                                    for sub in child:
                                        t_val = (sub.text or "").strip().upper()
                                        if RE_ATTACK.match(t_val):
                                            cwe_explicit_attack_refs.setdefault(cwe_key, set()).add(t_val)
                                    entry_id = child.get("Entry_ID", "").strip().upper()
                                    if RE_ATTACK.match(entry_id):
                                        cwe_explicit_attack_refs.setdefault(cwe_key, set()).add(entry_id)
                                elif "Related_Attack_Pattern" in ctag:
                                    t_val = (child.get("Technique_ID") or child.get("ATTACK_ID") or "").strip().upper()
                                    if RE_ATTACK.match(t_val):
                                        cwe_explicit_attack_refs.setdefault(cwe_key, set()).add(t_val)
                        elem.clear()

    cwe_docs: list[dict[str, Any]] = []
    shared_with_distractor: list[str] = []
    all_cves = target_cve_docs + distractor_cve_docs

    for cwe_id in sorted(referenced_cwe_ids):
        if not RE_CWE.match(cwe_id):
            add_skipped(cwe_id, "cwe", "INVALID_ID_FORMAT", "ID does not match CWE-NNN")
            continue
        if cwe_id not in cwe_catalog:
            add_skipped(cwe_id, "cwe", "CWE_NOT_IN_CATALOG", "ID not found in MITRE XML catalog")
            continue
        entry = cwe_catalog[cwe_id]
        desc = entry["description"]
        if not desc or not desc.strip():
            add_skipped(cwe_id, "cwe", "EMPTY_TEXT_FIELD", "No description in CWE catalog")
            continue

        is_target = cwe_id in target_cwe_set
        is_dist = cwe_id in distractor_cwe_ids
        if is_target and is_dist:
            shared_with_distractor.append(cwe_id)

        cwe_group = "positive" if is_target else "distractor"
        cwe_num = cwe_id.split("-")[1]

        rec = make_record(
            doc_id=cwe_id,
            doc_type="cwe",
            title=make_title(cwe_id, desc),
            text=desc,
            cve_ids=[d["doc_id"] for d in all_cves if cwe_id in d["cwe_ids"]],
            cwe_ids=[cwe_id],
            attack_ids=[],
            products=[],
            severity=None,
            cvss_score=None,
            cvss_version=None,
            known_exploited=None,
            published=None,
            last_modified=None,
            source="MITRE CWE",
            source_url=f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
            retrieved_at=cwe_ts,
            licence=LICENCE_CWE,
            group=cwe_group,
        )
        cwe_docs.append(rec)

    # 5. MITRE ATT&CK Enterprise STIX
    print("\n[Step 5/5] Downloading and parsing MITRE ATT&CK STIX bundle...")
    attack_stix_path = cache_dir / "enterprise-attack.json"
    attack_sha, attack_bytes, attack_elapsed, attack_ts = stream_download(
        URL_ATTACK_STIX, attack_stix_path, session, refresh=args.refresh
    )

    with open(attack_stix_path, "r", encoding="utf-8") as f:
        attack_bundle = json.load(f)

    attack_patterns, explicit_cwe_rels = parse_attack_bundle(attack_bundle)

    attack_candidates: list[str] = list(seed_attacks)
    for cwe_rec in cwe_docs:
        cwe_id = cwe_rec["doc_id"]
        for tech_id in sorted(cwe_explicit_attack_refs.get(cwe_id, set())):
            if (tech_id, cwe_id) in explicit_cwe_rels:
                if tech_id not in attack_candidates:
                    attack_candidates.append(tech_id)
                if cwe_rec["group"] == "distractor":
                    shared_with_distractor.append(tech_id)

    attack_docs: list[dict[str, Any]] = []
    seen_attack_ids: set[str] = set()

    for raw_tech in attack_candidates:
        tech_id = raw_tech.strip().upper()
        if tech_id in seen_attack_ids:
            continue
        rec, skip_info = process_attack_candidate(tech_id, attack_patterns, attack_ts)
        if skip_info:
            add_skipped(tech_id, "attack", skip_info[0], skip_info[1])
            continue
        if rec:
            seen_attack_ids.add(tech_id)
            attack_docs.append(rec)

    # 6. ProjectDiscovery Nuclei Templates
    print("\n[Step 6/6] Streaming ProjectDiscovery Nuclei templates...")
    nuclei_zip_path = cache_dir / "nuclei-templates-main.zip"
    nuclei_sha, nuclei_bytes, nuclei_elapsed, nuclei_ts = stream_download(
        URL_NUCLEI_ZIP, nuclei_zip_path, session, refresh=args.refresh
    )

    nuclei_docs: list[dict[str, Any]] = []
    target_cve_ids = {d["doc_id"] for d in target_cve_docs}
    distractor_cve_ids_set = {d["doc_id"] for d in distractor_cve_docs}
    all_known_cves = target_cve_ids | distractor_cve_ids_set

    with zipfile.ZipFile(nuclei_zip_path, "r") as z:
        for member in z.infolist():
            if member.is_dir():
                continue
            fname_lower = member.filename.lower()
            if not (fname_lower.endswith(".yaml") or fname_lower.endswith(".yml")):
                continue

            with z.open(member) as f:
                try:
                    raw_content = f.read().decode("utf-8", errors="replace")
                    if "classification:" not in raw_content or "cve-id" not in raw_content:
                        continue
                    tmpl = yaml.safe_load(raw_content)
                except Exception:
                    continue

            if not isinstance(tmpl, dict):
                continue
            info = tmpl.get("info")
            if not isinstance(info, dict):
                continue
            classification = info.get("classification")
            if not isinstance(classification, dict):
                continue

            cve_val = classification.get("cve-id")
            if not cve_val:
                continue

            cves_in_tmpl: list[str] = []
            if isinstance(cve_val, str):
                cves_in_tmpl = [c.strip().upper() for c in cve_val.split(",") if c.strip()]
            elif isinstance(cve_val, list):
                cves_in_tmpl = [str(c).strip().upper() for c in cve_val if str(c).strip()]

            matched_cves = [c for c in cves_in_tmpl if c in all_known_cves]
            if not matched_cves:
                continue

            tmpl_id = str(tmpl.get("id", "")).strip() or Path(member.filename).stem
            desc = str(info.get("description", ""))
            if not desc or not desc.strip():
                add_skipped(f"nuclei:{tmpl_id}", "nuclei", "EMPTY_TEXT_FIELD", "No description in template")
                continue

            severity = info.get("severity")
            sev_str = str(severity).upper() if severity else None

            cvss_score = None
            if "cvss-score" in classification:
                try:
                    cvss_score = float(classification["cvss-score"])
                except (ValueError, TypeError):
                    pass

            parts = Path(member.filename).parts
            rel_repo_path = "/".join(parts[1:]) if len(parts) > 1 else member.filename

            is_target_linked = any(c in target_cve_ids for c in matched_cves)
            is_dist_linked = any(c in distractor_cve_ids_set for c in matched_cves)
            if is_target_linked and is_dist_linked:
                shared_with_distractor.append(f"nuclei:{tmpl_id}")

            nuclei_group = "positive" if is_target_linked else "distractor"
            doc_id_val = f"nuclei:{tmpl_id}"

            rec = make_record(
                doc_id=doc_id_val,
                doc_type="nuclei",
                title=make_title(doc_id_val, desc),
                text=desc,
                cve_ids=matched_cves,
                cwe_ids=[],
                attack_ids=[],
                products=[],
                severity=sev_str,
                cvss_score=cvss_score,
                cvss_version=None,
                known_exploited=any(c in kev_map for c in matched_cves),
                published=None,
                last_modified=None,
                source="ProjectDiscovery Nuclei",
                source_url=f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{rel_repo_path}",
                retrieved_at=nuclei_ts,
                licence=LICENCE_NUCLEI,
                group=nuclei_group,
            )
            nuclei_docs.append(rec)

    # 7. Deduplication in exact specified order:
    # target CVEs, distractor CVEs, CWE records, ATT&CK records, Nuclei records
    ordered_candidates = target_cve_docs + distractor_cve_docs + cwe_docs + attack_docs + nuclei_docs
    unique_docs: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for doc in ordered_candidates:
        d_id = doc["doc_id"]
        if d_id in seen_ids:
            add_skipped(d_id, doc["doc_type"], "DUPLICATE_DOC_ID", "Duplicate doc_id encountered")
            continue
        seen_ids.add(d_id)
        unique_docs.append(doc)

    # 8. Write outputs
    def write_jsonl(path: Path, docs: list[dict[str, Any]]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for d in docs:
                f.write(json.dumps(d, ensure_ascii=False) + "\n")

    canonical_path = out_dir / "documents.jsonl"
    write_jsonl(canonical_path, unique_docs)
    write_jsonl(out_dir / "cve.jsonl", [d for d in unique_docs if d["doc_type"] == "cve"])
    write_jsonl(out_dir / "distractor.jsonl", [d for d in unique_docs if d["doc_type"] == "distractor"])
    write_jsonl(out_dir / "cwe.jsonl", [d for d in unique_docs if d["doc_type"] == "cwe"])
    write_jsonl(out_dir / "attack.jsonl", [d for d in unique_docs if d["doc_type"] == "attack"])
    write_jsonl(out_dir / "nuclei.jsonl", [d for d in unique_docs if d["doc_type"] == "nuclei"])
    write_jsonl(out_dir / "skipped.jsonl", skipped_records)

    corpus_sha = compute_sha256(canonical_path) if canonical_path.is_file() else ""

    positive_cves = sum(1 for d in unique_docs if d["doc_type"] == "cve" and d["group"] == "positive")
    kev_cves = sum(1 for d in unique_docs if d["doc_type"] == "cve" and d["group"] == "kev")
    targets_total = positive_cves + kev_cves
    distractor_cves = sum(1 for d in unique_docs if d["doc_type"] == "distractor")
    cwe_records = sum(1 for d in unique_docs if d["doc_type"] == "cwe")
    attack_records = sum(1 for d in unique_docs if d["doc_type"] == "attack")
    nuclei_records = sum(1 for d in unique_docs if d["doc_type"] == "nuclei")

    manifest = {
        "sources": {
            "nvd": {
                "url": URL_NVD_API,
                "download_timestamp": datetime.now(timezone.utc).isoformat(),
                "sha256": "api-queried-per-cve",
                "size_bytes": sum(Path(nvd_cache_dir / f"{cid}.json").stat().st_size for cid in nvd_cached_shas if (nvd_cache_dir / f"{cid}.json").is_file()),
                "cached_files": nvd_cached_shas,
                "licence": LICENCE_NVD,
            },
            "cisa_kev": {
                "url": URL_CISA_KEV,
                "download_timestamp": cisa_ts,
                "sha256": cisa_sha,
                "size_bytes": cisa_bytes,
                "licence": LICENCE_CISA,
            },
            "cwe": {
                "url": URL_CWE_ZIP,
                "download_timestamp": cwe_ts,
                "sha256": cwe_sha,
                "size_bytes": cwe_bytes,
                "catalog_version": catalog_version,
                "licence": LICENCE_CWE,
            },
            "attack": {
                "url": URL_ATTACK_STIX,
                "download_timestamp": attack_ts,
                "sha256": attack_sha,
                "size_bytes": attack_bytes,
                "licence": LICENCE_ATTACK,
            },
            "nuclei": {
                "url": URL_NUCLEI_ZIP,
                "download_timestamp": nuclei_ts,
                "sha256": nuclei_sha,
                "size_bytes": nuclei_bytes,
                "licence": LICENCE_NUCLEI,
            },
        },
        "cwe": {
            "catalog_version": catalog_version,
        },
        "accounting": {
            "positive_cves": positive_cves,
            "kev_cves": kev_cves,
            "targets_total": targets_total,
            "distractor_cves": distractor_cves,
            "cwe_records": cwe_records,
            "attack_records": attack_records,
            "nuclei_records": nuclei_records,
            "total_documents": len(unique_docs),
        },
        "distractor_matches": distractor_matches,
        "shared_with_distractor": sorted(list(set(shared_with_distractor))),
        "text_transformations": [],
        "corpus_sha256": corpus_sha,
    }

    with open(out_dir / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    # 9. Summary Table
    print("\n" + "=" * 74)
    print(f"{'Source':<24} {'Requested':>10} {'Found':>9} {'Skipped':>10} {'Written':>9}")
    print("=" * 74)

    req_target = len(seed_cves)
    found_target = len(target_cve_docs)
    skip_target = sum(1 for s in skipped_records if s["type"] == "cve")
    written_target = targets_total
    print(f"{'NVD Target CVEs':<24} {req_target:>10} {found_target:>9} {skip_target:>10} {written_target:>9}")

    req_dist = len(seed_distractors)
    found_dist = len(distractor_cve_docs)
    skip_dist = sum(1 for s in skipped_records if s["type"] == "distractor")
    written_dist = distractor_cves
    print(f"{'NVD Distractors':<24} {req_dist:>10} {found_dist:>9} {skip_dist:>10} {written_dist:>9}")

    req_cwe = len(referenced_cwe_ids)
    found_cwe = len(cwe_docs)
    skip_cwe = sum(1 for s in skipped_records if s["type"] == "cwe")
    written_cwe = cwe_records
    print(f"{'MITRE CWE':<24} {req_cwe:>10} {found_cwe:>9} {skip_cwe:>10} {written_cwe:>9}")

    req_att = len(seed_attacks)
    found_att = len(attack_docs)
    skip_att = sum(1 for s in skipped_records if s["type"] == "attack")
    written_att = attack_records
    print(f"{'MITRE ATT&CK':<24} {req_att:>10} {found_att:>9} {skip_att:>10} {written_att:>9}")

    found_nuc = len(nuclei_docs)
    skip_nuc = sum(1 for s in skipped_records if s["type"] == "nuclei")
    written_nuc = nuclei_records
    print(f"{'Nuclei Templates':<24} {'matched':>10} {found_nuc:>9} {skip_nuc:>10} {written_nuc:>9}")
    print("=" * 74)
    print(f"Total Unique Documents: {len(unique_docs)}")
    print(f"Output files saved in: {out_dir.resolve()}\n")

    if targets_total > 0 and distractor_cves < 0.10 * targets_total:
        print(f"[WARNING] Distractor CVE count ({distractor_cves}) is below 10% of target CVE count ({targets_total}). A weak distractor set weakens the retrieval test.\n")

    if len(unique_docs) == 0:
        print("[ERROR] documents.jsonl has zero records. The seed files are empty or no valid records were found.")
        sys.exit(1)


if __name__ == "__main__":
    main()
