from __future__ import annotations

import queue
import json
import threading
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from .config import settings
from .db import Job, db_session, init_db, now


@dataclass
class Work:
    job_id: int
    fn: Callable[[], str]
    future: Future[str]


class JobQueue:
    def __init__(self) -> None:
        self._queue: queue.Queue[Work] = queue.Queue()
        self._cancelled: set[int] = set()
        self._lock = threading.Lock()
        threading.Thread(target=self._worker, daemon=True, name="job-worker").start()

    def enqueue(
        self,
        job_type: str,
        target: str,
        fn: Callable[[], str],
        *,
        target_hostname: str = "",
        resolved_ip: str = "",
        public_target: bool = False,
        authorized: bool = False,
        tools: list[str] | None = None,
    ) -> int:
        with db_session() as db:
            job = Job(
                type=job_type,
                target=target,
                target_hostname=target_hostname,
                resolved_ip=resolved_ip,
                public_target=public_target,
                authorized=authorized,
                created_at=now(),
                timestamp=now(),
                tools=json.dumps(tools or []),
                status="queued",
            )
            db.add(job)
            db.commit()
            job_id = job.id
        self._queue.put(Work(job_id, fn, Future()))
        return job_id

    def cancel(self, job_id: int) -> bool:
        with self._lock:
            self._cancelled.add(job_id)
        with db_session() as db:
            job = db.get(Job, job_id)
            if not job or job.status not in {"queued", "running"}:
                return False
            job.status = "cancelled"
            job.finished_at = now()
            job.message = "Cancelled"
            db.commit()
        return True

    def is_cancelled(self, job_id: int) -> bool:
        with self._lock:
            return job_id in self._cancelled

    def _worker(self) -> None:
        while True:
            work = self._queue.get()
            with db_session() as db:
                job = db.get(Job, work.job_id)
                if not job or job.status == "cancelled":
                    self._queue.task_done()
                    continue
                job.status, job.started_at = "running", now()
                db.commit()
            try:
                if work.job_id in self._cancelled:
                    raise RuntimeError("Cancelled")
                result_holder: list[str] = []
                error_holder: list[BaseException] = []
                task = threading.Thread(target=lambda: self._run_work(work.fn, result_holder, error_holder), daemon=True)
                task.start()
                task.join(settings.job_timeout_seconds)
                if task.is_alive():
                    with db_session() as db:
                        job = db.get(Job, work.job_id)
                        if job:
                            job.status, job.message, job.finished_at = "failed", f"Job exceeded {settings.job_timeout_seconds} seconds", now()
                            db.commit()
                    task.join()
                    continue
                if error_holder:
                    raise error_holder[0]
                result = result_holder[0] if result_holder else ""
                with db_session() as db:
                    job = db.get(Job, work.job_id)
                with db_session() as db:
                    job = db.get(Job, work.job_id)
                    if job and job.status != "cancelled":
                        job.status, job.message = "done", result or "Completed"
                        job.finished_at = now()
                        db.commit()
            except Exception as exc:
                with db_session() as db:
                    job = db.get(Job, work.job_id)
                    if job and job.status != "cancelled":
                        job.status, job.message = "failed", str(exc)
                        job.finished_at = now()
                        db.commit()
            finally:
                self._queue.task_done()

    @staticmethod
    def _run_work(fn: Callable[[], str], result_holder: list[str], error_holder: list[BaseException]) -> None:
        try:
            result_holder.append(fn())
        except BaseException as exc:
            error_holder.append(exc)


job_queue = JobQueue()
init_db()
