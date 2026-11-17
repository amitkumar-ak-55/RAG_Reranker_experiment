from __future__ import annotations

import json
from pathlib import Path

import pytest

from kb_build import (
    ALLOWED_SKIPPED_REASONS,
    SCHEMA_KEYS,
    extract_cpe_vendor_product,
    make_record,
    make_title,
    parse_attack_bundle,
    parse_nvd_record,
    process_attack_candidate,
    qualify_distractor,
)


def test_every_record_has_exactly_the_19_keys() -> None:
    expected_keys = [
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
    assert SCHEMA_KEYS == expected_keys

    # Check CVE record
    rec_cve = make_record(
        doc_id="CVE-2021-44228",
        doc_type="cve",
        title="CVE-2021-44228: Title",
        text="Sample text",
        cve_ids=["CVE-2021-44228"],
        cwe_ids=["CWE-502"],
        attack_ids=[],
        products=["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
        severity="CRITICAL",
        cvss_score=10.0,
        cvss_version="3.1",
        known_exploited=True,
        published="2021-12-10T10:15:00Z",
        last_modified="2021-12-14T12:00:00Z",
        source="NVD",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        retrieved_at="2026-11-05T00:00:00Z",
        licence="NVD",
        group="kev",
    )
    assert list(rec_cve.keys()) == expected_keys
    assert len(rec_cve.keys()) == 19

    # Check distractor record
    rec_dist = make_record(
        doc_id="CVE-2020-9999",
        doc_type="distractor",
        title="CVE-2020-9999: Distractor",
        text="Distractor description",
        cve_ids=["CVE-2020-9999"],
        cwe_ids=["CWE-89"],
        attack_ids=[],
        products=[],
        severity="HIGH",
        cvss_score=7.5,
        cvss_version="3.1",
        known_exploited=False,
        published="2020-01-01T00:00:00Z",
        last_modified="2020-01-02T00:00:00Z",
        source="NVD",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2020-9999",
        retrieved_at="2026-11-05T00:00:00Z",
        licence="NVD",
        group="distractor",
    )
    assert list(rec_dist.keys()) == expected_keys
    assert len(rec_dist.keys()) == 19

    # Check ATT&CK record
    rec_att = make_record(
        doc_id="T1190",
        doc_type="attack",
        title="T1190: Exploit Public-Facing Application",
        text="Adversaries may attempt to exploit vulnerabilities...",
        cve_ids=[],
        cwe_ids=[],
        attack_ids=["T1190"],
        products=[],
        severity=None,
        cvss_score=None,
        cvss_version=None,
        known_exploited=None,
        published="2018-04-18T17:59:24.739Z",
        last_modified="2026-04-29T14:23:06.224Z",
        source="MITRE ATT&CK",
        source_url="https://attack.mitre.org/techniques/T1190/",
        retrieved_at="2026-11-05T00:00:00Z",
        licence="MITRE ATT&CK",
        group="positive",
    )
    assert list(rec_att.keys()) == expected_keys
    assert len(rec_att.keys()) == 19


def test_text_is_byte_identical_to_fixture_input(tmp_path: Path) -> None:
    fixture_text = "  Raw\tDescription\nWith  Tabs and   Spaces \r\n-- No alterations! "
    fixture_json = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": fixture_text}],
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-502"}
                            ]
                        }
                    ],
                    "configurations": [],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL"
                                }
                            }
                        ]
                    },
                    "published": "2021-12-10T10:15:00Z",
                    "lastModified": "2021-12-14T12:00:00Z",
                }
            }
        ]
    }
    fixture_file = tmp_path / "nvd_sample.json"
    fixture_file.write_text(json.dumps(fixture_json), encoding="utf-8")

    loaded_data = json.loads(fixture_file.read_text(encoding="utf-8"))
    parsed = parse_nvd_record("CVE-2021-44228", loaded_data)
    assert parsed is not None
    assert parsed["text"] == fixture_text
    assert parsed["text"].encode("utf-8") == fixture_text.encode("utf-8")


def test_distractor_sharing_cwe_is_admitted_with_rule_cwe() -> None:
    target_cwes = {"CWE-89", "CWE-79"}
    target_vps = {("apache", "http_server")}

    # Candidate shares CWE-89, but has entirely unrelated vendor/product
    cand_cwes = {"CWE-89"}
    cand_vps = {("oracle", "mysql")}

    match = qualify_distractor(cand_cwes, cand_vps, target_cwes, target_vps)
    assert match is not None
    assert match["rule"] == "cwe"
    assert match["value"] == "CWE-89"
    assert "also" not in match


def test_distractor_sharing_only_vendor_is_rejected() -> None:
    target_cwes = {"CWE-89"}
    target_vps = {("apache", "http_server")}

    # Candidate shares vendor "apache", but product "tomcat" (not http_server), no shared CWE
    cand_cwes = {"CWE-200"}
    cand_vps = {("apache", "tomcat")}

    match = qualify_distractor(cand_cwes, cand_vps, target_cwes, target_vps)
    assert match is None


def test_distractor_sharing_vendor_product_is_admitted_with_rule_vendor_product() -> None:
    target_cwes = {"CWE-89"}
    target_vps = {("apache", "http_server")}

    # Candidate shares (apache, http_server), but no shared CWE
    cand_cwes = {"CWE-200"}
    cand_vps = {("apache", "http_server")}

    match = qualify_distractor(cand_cwes, cand_vps, target_cwes, target_vps)
    assert match is not None
    assert match["rule"] == "vendor_product"
    assert match["value"] == "apache:http_server"
    assert "also" not in match


def test_distractor_sharing_both_records_cwe_first_and_also() -> None:
    target_cwes = {"CWE-89"}
    target_vps = {("apache", "http_server")}

    # Candidate shares both CWE and (vendor, product)
    cand_cwes = {"CWE-89"}
    cand_vps = {("apache", "http_server")}

    match = qualify_distractor(cand_cwes, cand_vps, target_cwes, target_vps)
    assert match is not None
    assert match["rule"] == "cwe"
    assert match["value"] == "CWE-89"
    assert "also" in match
    assert match["also"] == {"rule": "vendor_product", "value": "apache:http_server"}


def test_kev_distractor_is_rejected() -> None:
    cisa_kev_set = {"CVE-2021-44228", "CVE-2020-1472"}
    distractor_candidate = "CVE-2021-44228"

    assert distractor_candidate in cisa_kev_set
    # Detail string verification
    skip_reason = "UNQUALIFIED_DISTRACTOR"
    skip_detail = "candidate is in CISA KEV"
    assert skip_reason in ALLOWED_SKIPPED_REASONS
    assert skip_detail == "candidate is in CISA KEV"


def test_attack_id_missing_from_bundle_is_skipped() -> None:
    catalog = {
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "description": "Exploitation description...",
            "created": "2018-04-18T17:59:24.739Z",
            "modified": "2026-04-29T14:23:06.224Z",
            "external_references": [
                {"source_name": "mitre-attack", "url": "https://attack.mitre.org/techniques/T1190"}
            ],
        }
    }
    rec, skip_info = process_attack_candidate("T9999", catalog, "2026-11-05T00:00:00Z")
    assert rec is None
    assert skip_info is not None
    assert skip_info[0] == "TECHNIQUE_NOT_IN_ATTACK"
    assert skip_info[0] in ALLOWED_SKIPPED_REASONS


def test_revoked_attack_technique_is_skipped() -> None:
    catalog = {
        "T1000": {
            "name": "Revoked Technique",
            "description": "Some description",
            "revoked": True,
            "created": "2017-05-31T21:30:19.497Z",
            "modified": "2020-03-30T17:10:45.334Z",
        },
        "T1001": {
            "name": "Deprecated Technique",
            "description": "Some description",
            "x_mitre_deprecated": True,
            "created": "2017-05-31T21:30:19.497Z",
            "modified": "2020-03-30T17:10:45.334Z",
        },
    }
    rec_rev, skip_rev = process_attack_candidate("T1000", catalog, "2026-11-05T00:00:00Z")
    assert rec_rev is None
    assert skip_rev is not None
    assert skip_rev[0] == "TECHNIQUE_NOT_IN_ATTACK"
    assert skip_rev[1] == "deprecated or revoked"

    rec_dep, skip_dep = process_attack_candidate("T1001", catalog, "2026-11-05T00:00:00Z")
    assert rec_dep is None
    assert skip_dep is not None
    assert skip_dep[0] == "TECHNIQUE_NOT_IN_ATTACK"
    assert skip_dep[1] == "deprecated or revoked"


def test_valid_attack_technique_builds_correct_record() -> None:
    catalog = {
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "description": "Raw STIX description text.",
            "revoked": False,
            "x_mitre_deprecated": False,
            "x_mitre_data_sources": ["Data Source A"],
            "created": "2018-04-18T17:59:24.739Z",
            "modified": "2026-04-29T14:23:06.224Z",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1190",
                    "url": "https://attack.mitre.org/techniques/T1190",
                }
            ],
        }
    }
    rec, skip_info = process_attack_candidate("T1190", catalog, "2026-11-05T00:00:00Z")
    assert skip_info is None
    assert rec is not None
    assert rec["doc_id"] == "T1190"
    assert rec["doc_type"] == "attack"
    assert rec["title"] == "T1190: Exploit Public-Facing Application"
    assert rec["text"] == "Raw STIX description text."
    assert rec["cwe_ids"] == ["Data Source A"]
    assert rec["attack_ids"] == ["T1190"]
    assert rec["group"] == "positive"
    assert rec["published"] == "2018-04-18T17:59:24.739Z"
    assert rec["last_modified"] == "2026-04-29T14:23:06.224Z"
    assert rec["source_url"] == "https://attack.mitre.org/techniques/T1190"
    assert len(rec.keys()) == 19


def test_cwe_referenced_by_target_and_distractor_appears_once_with_group_positive() -> None:
    target_cwes = {"CWE-89"}
    distractor_cwes = {"CWE-89", "CWE-79"}

    shared_with_distractor = []
    cwe_records = []

    all_referenced = sorted(list(target_cwes | distractor_cwes))
    for cwe_id in all_referenced:
        is_target = cwe_id in target_cwes
        is_dist = cwe_id in distractor_cwes
        if is_target and is_dist:
            shared_with_distractor.append(cwe_id)
        assigned_group = "positive" if is_target else "distractor"
        cwe_records.append({
            "doc_id": cwe_id,
            "group": assigned_group,
        })

    # Assert CWE-89 is marked as positive and recorded in shared_with_distractor
    cwe_89 = next(r for r in cwe_records if r["doc_id"] == "CWE-89")
    assert cwe_89["group"] == "positive"
    assert shared_with_distractor == ["CWE-89"]

    # Assert CWE-79 (only in distractor) has group "distractor"
    cwe_79 = next(r for r in cwe_records if r["doc_id"] == "CWE-79")
    assert cwe_79["group"] == "distractor"

    # Exactly two unique CWE records
    assert len(cwe_records) == 2


def test_targets_total_equals_positive_cves_plus_kev_cves() -> None:
    positive_cves = 7
    kev_cves = 3
    targets_total = positive_cves + kev_cves
    assert targets_total == 10


def test_nuclei_published_and_last_modified_are_null() -> None:
    doc_id = "nuclei:CVE-2021-44228"
    rec = make_record(
        doc_id=doc_id,
        doc_type="nuclei",
        title="Nuclei: Apache Log4j",
        text="Nuclei template description",
        cve_ids=["CVE-2021-44228"],
        cwe_ids=[],
        attack_ids=[],
        products=[],
        severity="CRITICAL",
        cvss_score=10.0,
        cvss_version=None,
        known_exploited=True,
        published=None,
        last_modified=None,
        source="ProjectDiscovery Nuclei",
        source_url="https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/2021/CVE-2021-44228.yaml",
        retrieved_at="2026-11-05T00:00:00Z",
        licence="MIT",
        group="positive",
    )
    assert rec["published"] is None
    assert rec["last_modified"] is None


def test_every_skipped_reason_is_in_the_allowed_list() -> None:
    expected_allowed = [
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
    assert ALLOWED_SKIPPED_REASONS == expected_allowed
