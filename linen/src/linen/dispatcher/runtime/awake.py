"""Keep local macOS workers schedulable without changing power settings."""

from __future__ import annotations

import logging
import os
import subprocess
import sys

LOG = logging.getLogger(__name__)


class IdleSleepGuard:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        if not self.enabled or sys.platform != "darwin" or self.process is not None:
            return
        try:
            self.process = subprocess.Popen(
                ["/usr/bin/caffeinate", "-i", "-w", str(os.getpid())],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True,
            )
        except OSError as exc:
            LOG.warning("idle sleep guard unavailable: %s", exc)
        else:
            LOG.info("preventing macOS idle sleep while dispatcher runs pid=%s", self.process.pid)

    def close(self) -> None:
        process, self.process = self.process, None
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
