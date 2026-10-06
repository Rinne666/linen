from __future__ import annotations

import random

from linen.dispatcher.config import WorkerConfig


def choose_worker(candidates: list[WorkerConfig], running_counts: dict[str, int]) -> list[WorkerConfig]:
    """Order candidate workers most-preferred first.

    A higher ``priority`` always wins, which is how an operator pins a
    preferred CLI (e.g. codex) ahead of the others. Workers that share a
    priority are then ordered by live load and finally at random, so equal
    preferences still spread work instead of always hitting one worker.
    An unset ``priority`` ranks as 0.
    """
    grouped = sorted(
        candidates,
        key=lambda worker: (
            -(worker.priority or 0),
            running_counts.get(worker.name, 0),
            random.random(),
        ),
    )
    return grouped
