from pathlib import Path


HTML_PATH = Path(__file__).parents[2] / "src" / "linen" / "server" / "static" / "index.html"


def html() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


def test_execution_indicator_uses_live_work_state_not_project_lifecycle() -> None:
    source = html()
    status_rail = source[
        source.index('aria-label="Project execution status"') : source.index("primaryProjectError()")
    ]

    assert ':class="executionStatusDotClass()"' in status_rail
    assert 'x-text="executionStatusLabel()"' in status_rail
    assert "project.project.status === 'active' ? 'bg-emerald-500'" not in status_rail
    assert "if (working) return `${working} worker${working === 1 ? '' : 's'} running`;" in source
    assert "return 'No worker running';" in source


def test_status_rail_surfaces_current_work_recent_activity_and_audit_progress() -> None:
    source = html()
    status_rail = source[
        source.index('aria-label="Project execution status"') : source.index("primaryProjectError()")
    ]

    assert ">Current work</div>" in status_rail
    assert ">Last activity</div>" in status_rail
    assert 'x-text="lastActivityLabel()"' in status_rail
    assert ">Audit progress</div>" in status_rail
    assert 'x-text="auditProgressLabel()"' in status_rail


def test_audit_progress_uses_real_stage_and_gate_counts() -> None:
    source = html()

    assert 'x-text="auditStageProgressLabel()"' in source
    assert 'x-text="completionCheckProgressLabel()"' in source
    assert "['pass', 'not_applicable'].includes(check.status)" in source
    assert "Complete ${requiredStages.length} required audit stage" in source
    assert "No worker is running" in source


def test_on_demand_scanners_are_not_presented_as_required_progress() -> None:
    source = html()

    assert "tools on demand" in source
    assert "No required stages" in source
    assert ">On demand</span>" in source


def test_reviewed_candidate_blocker_exposes_technical_confirmation_action() -> None:
    source = html()

    assert "technicalConfirmationCandidates().length" in source
    assert "Review passed · technical proof not yet confirmed" in source
    assert "Run technical confirmation" in source
    assert "confirmReviewedFinding(fact.id)" in source
    assert "`/projects/${this.selectedProjectId}/facts/${factId}/technical-confirmation`" in source
    assert "technicalConfirmationFailureMessage(error)" in source
    assert "Select reviewed evidence for completion" not in source
    assert "`${completionGate.blockers.length} blocker${completionGate.blockers.length === 1 ? '' : 's'}`" in source


def test_confirmed_finding_count_does_not_promote_current_candidate_by_status() -> None:
    source = html()
    start = source.index("confirmedFindingCount() {")
    end = source.index("completionGateLabel()", start)
    counter = source[start:end]

    assert "fact.semantic_type === 'confirmed_finding'" in counter
    assert "fact.legacy && fact.type === 'vulnerability'" in counter
    assert "|| (fact.type === 'vulnerability'" not in counter


def test_activity_loader_starts_near_latest_event_and_then_fetches_incrementally() -> None:
    source = html()
    loader = source[source.index("async loadAuditEvents(") : source.index("async loadProjectReviews(")]

    assert "const latestLoaded = currentEvents.reduce(" in loader
    assert "const after = latestLoaded || Math.max(0, projectEventSeq - 500);" in loader
    assert "`/projects/${projectId}/events?after=${after}&limit=500`" in loader
    assert "eventsBySequence.set(event.sequence, event)" in loader
