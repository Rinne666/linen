from __future__ import annotations

import threading
import time

from linen.dispatcher.runtime.process import ExecProcess

CANCELLATION_CLEANUP_GRACE_SECONDS = 20


class TaskCancellation:
    def __init__(
        self,
        *,
        deadline_epoch: float | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._process: ExecProcess | None = None
        self._reason: str | None = None
        self._deadline_epoch = deadline_epoch
        self._deadline_timer: threading.Timer | None = None
        if deadline_epoch is not None:
            delay = max(0.0, deadline_epoch - time.time())
            self._deadline_timer = threading.Timer(
                delay, self.cancel, args=("audit_wall_clock_budget_exhausted",),
            )
            self._deadline_timer.daemon = True
            self._deadline_timer.start()

    def attach_process(self, process: ExecProcess | None) -> None:
        with self._lock:
            self._process = process
            reason = self._reason
        if process is not None and reason is not None:
            process.cancel(reason)

    def start_process(self, process: ExecProcess) -> bool:
        """Atomically refuse process start once cancelled or past its deadline.

        The lock closes the small race between a runner's preflight check and
        `Popen`: a deadline callback either observes the attached process and
        terminates it, or this method observes the elapsed deadline and never
        starts it.
        """
        with self._lock:
            if (
                self._reason is None
                and self._deadline_epoch is not None
                and time.time() >= self._deadline_epoch
            ):
                self._reason = "audit_wall_clock_budget_exhausted"
            if self._reason is not None:
                return False
            self._process = process
            process.start()
            return True

    def cancel(self, reason: str) -> bool:
        with self._lock:
            already_cancelled = self._reason is not None
            if not already_cancelled:
                self._reason = reason
                process = self._process
            else:
                process = None
        if process is not None:
            process.cancel(reason)
        return not already_cancelled

    def close(self) -> None:
        """Release the budget timer after its owning scheduled task finishes."""
        timer = self._deadline_timer
        self._deadline_timer = None
        if timer is not None:
            timer.cancel()

    def clamp_timeout(self, timeout_seconds: int) -> int:
        """Limit one worker phase to the remaining project wall-clock budget."""
        remaining = self.remaining_seconds()
        if remaining is None:
            return timeout_seconds
        if remaining <= 0:
            self.cancel("audit_wall_clock_budget_exhausted")
            return 1
        return min(timeout_seconds, max(1, int(remaining)))

    def remaining_seconds(self) -> float | None:
        if self._deadline_epoch is None:
            return None
        return self._deadline_epoch - time.time()

    @property
    def is_cancelled(self) -> bool:
        return self.reason is not None

    @property
    def reason(self) -> str | None:
        with self._lock:
            return self._reason
