"""Background jobs for the GUI (scan, malware check, fix): one at a time, with a live log."""
from __future__ import annotations

import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from scs.util import JobCancelled, add_log_sink, remove_log_sink

CANCELLABLE = ("scan", "malware")  # read-only work; fixes are never interrupted half-way


@dataclass
class Job:
    kind: str
    title: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    state: str = "running"      # running | done | failed | cancelled
    started: float = field(default_factory=time.time)
    finished: Optional[float] = None
    log: list[str] = field(default_factory=list)
    result: Any = None
    error: str = ""

    cancel_requested: bool = False
    last_progress: float = field(default_factory=time.time)

    def append(self, line: str) -> None:
        for part in str(line).splitlines() or [""]:
            self.log.append(part)
        self.last_progress = time.time()
        if self.cancel_requested:
            raise JobCancelled()

    def view(self, since: int = 0) -> dict:
        return {"id": self.id, "kind": self.kind, "title": self.title, "state": self.state, "started": self.started,
                "finished": self.finished, "log": self.log[since:], "log_size": len(self.log), "error": self.error,
                "elapsed": round((self.finished or time.time()) - self.started),
                "idle": round(time.time() - self.last_progress), "cancellable": self.kind in CANCELLABLE,
                "cancel_requested": self.cancel_requested,
                "result": self.result if self.state != "running" else None}


class Busy(Exception):
    pass


class JobManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.current: Optional[Job] = None
        self.jobs: dict[str, Job] = {}

    def start(self, kind: str, title: str, fn: Callable[[Job], Any]) -> Job:
        with self.lock:
            if self.current and self.current.state == "running":
                raise Busy(f"{self.current.title} is still running")
            job = Job(kind, title)
            self.current = job
            self.jobs[job.id] = job

        def runner() -> None:
            sink = job.append
            add_log_sink(sink)
            try:
                job.result = fn(job)
                job.state = "done"
            except JobCancelled:
                job.log.append("Cancelled.")
                job.state = "cancelled"
            except Exception as e:  # surfaced to the UI, never crashes the server
                job.error = f"{e}"
                job.append(traceback.format_exc(limit=3))
                job.state = "failed"
            finally:
                remove_log_sink(sink)
                job.finished = time.time()

        threading.Thread(target=runner, daemon=True, name=f"scs-job-{kind}").start()
        return job

    def cancel(self, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if not job:
            raise KeyError("no such job")
        if job.kind not in CANCELLABLE:
            raise ValueError("updates cannot be stopped half-way; they undo themselves if something fails")
        job.cancel_requested = True  # takes effect at the next progress message
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)
