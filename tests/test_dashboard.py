from fastapi.testclient import TestClient

from rag_verify_lab.app import app


def test_dashboard_exposes_all_primary_experiment_arms() -> None:
    page = TestClient(app).get("/")

    assert page.status_code == 200
    for arm_id in ("armA", "armC", "armD", "armE"):
        assert f'id={arm_id}' in page.text
    assert "arms.push('llm_only')" in page.text
    assert "arms.push('hybrid_jev')" in page.text
    assert "JSON.stringify({type:'experiment',ids,arms})}).then" in page.text
    assert "JSON.stringify({type:'experiment',ids,arms})).then" not in page.text
