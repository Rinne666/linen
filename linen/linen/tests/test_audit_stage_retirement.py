from __future__ import annotations

from linen.dispatcher.analysis import stages
from linen.dispatcher.config import AuditConfig
from linen.server.models import AuditStage, ProjectDetail, ProjectMeta


def test_reconcile_retires_stage_removed_from_current_dispatcher(tmp_path) -> None:
    project = ProjectDetail(
        project=ProjectMeta(
            id="proj_001",
            title="audit",
            status="active",
            audit_mode="scope",
            created_at="2026-01-01T00:00:00Z",
        ),
        facts=[],
        intents=[],
        hints=[],
        stages=[
            AuditStage(
                stage_id="semgrep",
                label="Semgrep",
                phase_order=40,
                required=False,
                status="pending",
                capability="static-analysis.sarif",
                updated_at="2026-01-01T00:00:00Z",
            ),
        ],
    )

    rows = stages.reconcile(AuditConfig(enabled=True), project, tmp_path)
    retired = next(row for row in rows if row["stage_id"] == "semgrep")

    assert retired["required"] is False
    assert retired["status"] == "not_applicable"
    assert "Retired stage" in retired["detail"]
    assert retired in stages.changed_rows(project, rows)
