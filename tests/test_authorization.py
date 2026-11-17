import time

import pytest
from fastapi.testclient import TestClient

from rag_verify_lab.app import app
from rag_verify_lab.db import Job, db_session
from rag_verify_lab.jobs import JobQueue
from rag_verify_lab.scan.nmap_runner import validate_target


def test_scan_requires_authorization() -> None:
    response = TestClient(app).post("/api/scan", json={"target": "192.0.2.1", "authorized": False})
    assert response.status_code == 400


@pytest.mark.parametrize("target", ["192.0.2.1", "example.test", "192.0.2.0/24", "192.0.2.0/32"])
def test_scan_target_formats_are_accepted(target: str) -> None:
    assert validate_target(target) == target


@pytest.mark.parametrize("target", ["10.0.0.0/8", "not a host!"])
def test_scan_target_formats_are_rejected(target: str) -> None:
    with pytest.raises(ValueError):
        validate_target(target)


def test_scan_job_stores_authorization_and_metadata() -> None:
    queue = JobQueue()
    job_id = queue.enqueue(
        "scan",
        "example.test",
        lambda: "done",
        target_hostname="example.test",
        resolved_ip="192.0.2.1",
        authorized=True,
        tools=["nmap", "nuclei"],
    )
    time.sleep(0.2)
    with db_session() as db:
        job = db.get(Job, job_id)
        assert job is not None
        assert job.target == "example.test"
        assert job.resolved_ip == "192.0.2.1"
        assert job.authorized is True
        assert job.tools == '["nmap", "nuclei"]'
        assert job.created_at is not None
        assert job.timestamp is not None
