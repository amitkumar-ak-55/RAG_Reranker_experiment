from rag_verify_lab.verify.claims import citation_correctness, unsupported_rate


def test_claim_metrics() -> None:
    claims = [{"label": "SUPPORTED", "citation_correct": True}, {"label": "UNSUPPORTED", "citation_correct": False}, {"label": "CONTRADICTED", "citation_correct": True}]
    assert unsupported_rate(claims) == 2 / 3
    assert citation_correctness(claims) == 2 / 3
