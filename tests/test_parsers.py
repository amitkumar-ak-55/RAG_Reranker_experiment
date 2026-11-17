from rag_verify_lab.scan.nmap_runner import parse_nmap_xml
from rag_verify_lab.scan.nuclei_runner import parse_nuclei_jsonl


def test_nmap_parser() -> None:
    findings = parse_nmap_xml('<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="demo" version="1"/></port></ports></host></nmaprun>')
    assert findings[0].ip == "127.0.0.1" and findings[0].port == 80


def test_nuclei_parser() -> None:
    findings = parse_nuclei_jsonl('{"template-id":"x","host":"127.0.0.1","matched-at":"http://127.0.0.1","info":{"name":"Demo","severity":"high","classification":{"cve-id":["CVE-1"]}}}')
    assert findings[0].cve_id == "CVE-1"
