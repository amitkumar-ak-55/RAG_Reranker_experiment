import threading
import time

from rag_verify_lab.jobs import JobQueue
from rag_verify_lab.db import db_session, Job


def test_queue_runs_one_at_a_time_and_cancel() -> None:
    q = JobQueue()
    gate = threading.Event()
    active = []

    def work() -> str:
        active.append(1)
        gate.wait(1)
        active.pop()
        return "ok"

    first, second = q.enqueue("test", "", work), q.enqueue("test", "", work)
    assert q.cancel(second)
    gate.set()
    time.sleep(0.2)
    with db_session() as db:
        assert db.get(Job, first).status == "done"
        assert db.get(Job, second).status == "cancelled"
    assert not active
