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


@dataclass(slots=True)
class ReasonCheckpoint:
    fact_count: int
    hint_count: int
    open_intent_count: int
    graph_revision: int = 0
    review_count: int = 0


@dataclass(slots=True)
class AuditGraphCheckpoint:
    graph_revision: int
    attempts: int
