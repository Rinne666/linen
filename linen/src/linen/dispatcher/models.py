from __future__ import annotations

from dataclasses import dataclass

from linen.dispatcher.runtime.cancellation import TaskCancellation


@dataclass(slots=True)
class RunningTask:
    project_id: str
    task_type: str
    worker_name: str
    cancellation: TaskCancellation
    intent_id: str | None = None
    intent_count: int | None = None
    graph_revision: int | None = None
    provider_required: bool = True
    # Optional vNext execution identity.  Kept additive so older scheduler
    # tests/embedders using positional RunningTask construction remain valid.
    run_id: str | None = None
    attempt: int | None = None
    idempotency_key: str | None = None
    context_projection_id: str | None = None
    worker_manifest_digest: str | None = None
    # Stable scheduler cause used to reconstruct the same logical run.
    trigger: str | None = None
