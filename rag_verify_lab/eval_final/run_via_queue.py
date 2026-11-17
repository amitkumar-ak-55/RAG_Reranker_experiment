from __future__ import annotations

import os
import sys
import time
from dataclasses import replace

from .. import jobs
from ..db import Job, db_session
from .final_runner import run


def queued_run(run_id: str) -> tuple[int, str]:
    timeout = max(3600, int(os.getenv("FINAL_EVAL_JOB_TIMEOUT_SECONDS", "86400")))
    jobs.settings = replace(jobs.settings, job_timeout_seconds=timeout)
    job_id = jobs.job_queue.enqueue("experiment", run_id, lambda: str(run(run_id)))
    while True:
        with db_session() as db:
            job = db.get(Job, job_id)
            if job is None:
                raise RuntimeError(f"Experiment job {job_id} disappeared from the queue")
            status, message = job.status, job.message
        if status in {"done", "failed", "cancelled"}:
            return job_id, f"{status}: {message}"
        time.sleep(2)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m rag_verify_lab.eval_final.run_via_queue <run_id>")
    job_id, result = queued_run(sys.argv[1])
    print(f"job_id={job_id} {result}")
    raise SystemExit(0 if result.startswith("done:") else 1)
