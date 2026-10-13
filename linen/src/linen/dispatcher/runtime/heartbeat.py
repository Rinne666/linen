from __future__ import annotations

import logging
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from linen.dispatcher.protocol.client import ApiResult, LinenClient
from linen.dispatcher.runtime.process import ExecProcess


LOG = logging.getLogger(__name__)
HEARTBEAT_FAILURE_GRACE_MULTIPLIER = 2


@dataclass(slots=True)
class HeartbeatFailure:
    status_code: int | None
    text: str
    code: str | None = None
    seconds_since_success: float = 0.0


class HeartbeatLease:
    def __init__(
        self,
        heartbeat: Callable[[], ApiResult],
        scope: str,
        worker_name: str,
        interval: int,
    ):
        self._heartbeat = heartbeat
        self._scope = scope
        self._worker_name = worker_name
        self._interval = interval
        self._process: ExecProcess | None = None
        self._failure: HeartbeatFailure | None = None
        self._last_success_at = time.monotonic()
        self._last_success_wall = time.time()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, daemon=True)

    @classmethod
    def for_intent(
        cls,
        client: LinenClient,
        project_id: str,
        intent_id: str,
        worker_name: str,
        interval: int,
    ) -> "HeartbeatLease":
        return cls(
            heartbeat=lambda: client.heartbeat(project_id, intent_id, worker_name),
            scope=f"project={project_id} intent={intent_id}",
            worker_name=worker_name,
            interval=interval,
        )

    @classmethod
    def for_reason(
        cls,
        client: LinenClient,
        project_id: str,
        worker_name: str,
        lease_id: str,
        interval: int,
    ) -> "HeartbeatLease":
        return cls(
            heartbeat=lambda: client.reason_heartbeat(project_id, worker_name, lease_id),
            scope=f"project={project_id} reason lease={lease_id[:8]}",
            worker_name=worker_name,
            interval=interval,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1)

    def attach_process(self, process: ExecProcess | None) -> None:
        with self._lock:
            self._process = process
            failure = self._failure
        if process is not None and failure is not None:
            process.cancel(self._cancel_reason(failure))

    @property
    def failure(self) -> HeartbeatFailure | None:
        return self._failure

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                result = self._heartbeat()
            except Exception as exc:
                result = ApiResult(503, text=f"heartbeat request failed: {type(exc).__name__}")
                LOG.warning("heartbeat request raised scope=%s error=%s", self._scope, type(exc).__name__)
            if result.ok:
                self._last_success_at = time.monotonic()
                self._last_success_wall = time.time()
                continue
            if result.status_code in (403, 409):
                self._fail(result.status_code, result.text)
                return
            elapsed = time.monotonic() - self._last_success_at
            grace_seconds = max(float(self._interval), float(self._interval * HEARTBEAT_FAILURE_GRACE_MULTIPLIER))
            LOG.warning(
                "heartbeat transient failure scope=%s worker=%s status=%s elapsed=%.1fs grace=%.1fs",
                self._scope,
                self._worker_name,
                result.status_code,
                elapsed,
                grace_seconds,
            )
            if elapsed < grace_seconds:
                continue
            self._fail(result.status_code or None, result.text)
            return

    def _fail(self, status_code: int | None, text: str) -> None:
        code = None
        try:
            detail = json.loads(text).get("detail")
            if isinstance(detail, dict) and detail.get("code") in {
                "reason_lease_expired", "reason_lease_not_claimed", "reason_worker_mismatch", "reason_token_mismatch",
            }:
                code = detail["code"]
        except (ValueError, TypeError, AttributeError):
            pass
        self._failure = HeartbeatFailure(status_code, text, code, max(0.0, time.time() - self._last_success_wall))
        detail = " ".join(text.split())[:240]
        LOG.warning(
            "heartbeat failed scope=%s worker=%s status=%s code=%s seconds_since_success=%.1f detail=%s",
            self._scope,
            self._worker_name,
            status_code,
            code or "unknown",
            self._failure.seconds_since_success,
            detail or "-",
        )
        with self._lock:
            process = self._process
        if process is not None:
            process.cancel(self._cancel_reason(self._failure))

    @staticmethod
    def _cancel_reason(failure: HeartbeatFailure) -> str:
        reason = f"heartbeat_lease_lost:{failure.status_code or 'unknown'}"
        return f"{reason}:{failure.code}" if failure.code else reason
