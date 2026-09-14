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
    fact_count: int | None = None
    hint_count: int | None = None
    open_intent_count: int | None = None
    intent_count: int | None = None
    reason_profile: str = "default"
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


@dataclass(slots=True)
class ReasonCheckpoint:
    fact_count: int
    hint_count: int
    open_intent_count: int
    graph_revision: int = 0
    review_count: int = 0
    # Scheduler-owned retry state.  Defaults preserve compatibility with
    # checkpoints persisted/constructed before vNext retry wiring.
    attempts: int = 0
    last_attempt_failed: bool = False


@dataclass(slots=True)
class AuditGraphCheckpoint:
    graph_revision: int
    attempts: int
