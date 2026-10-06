from fastapi import APIRouter

from linen.server.db import get_conn
from linen.server.models import CreateHintRequest, Hint
from linen.server.audit_state import append_event
from linen.server.services import bump_graph_revision, check_project_hint_writable, next_hint_id, utcnow

router = APIRouter(tags=["hints"])


@router.post(
    "/projects/{project_id}/hints",
    response_model=Hint,
    status_code=201,
)
def create_hint(project_id: str, body: CreateHintRequest):
    with get_conn() as conn:
        check_project_hint_writable(conn, project_id)

        now = utcnow()
        hid = next_hint_id(conn, project_id)
        actor = body.creator.strip()
        event_type = (
            "dispatcher_hint_created"
            if actor in {"dispatcher", "dispatcher.compaction", "audit-policy"}
            else "human_hint_created"
        )
        conn.execute(
            "INSERT INTO hints (id, project_id, content, creator, created_at) VALUES (?, ?, ?, ?, ?)",
            (hid, project_id, body.content, body.creator, now),
        )
        bump_graph_revision(conn, project_id)
        append_event(
            conn,
            project_id,
            event_type,
            body.creator,
            entity_kind="hint",
            entity_id=hid,
            payload={"hint_id": hid},
            created_at=now,
        )
        return Hint(id=hid, content=body.content, creator=body.creator, created_at=now)
