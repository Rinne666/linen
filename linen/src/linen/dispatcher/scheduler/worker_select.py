from __future__ import annotations

import random

from linen.dispatcher.config import WorkerConfig


def choose_worker(candidates: list[WorkerConfig], running_counts: dict[str, int]) -> list[WorkerConfig]:
    grouped = sorted(
        candidates,
        key=lambda worker: (
            running_counts.get(worker.name, 0),
            random.random(),
        ),
    )
    return grouped
