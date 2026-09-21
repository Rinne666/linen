from pathlib import Path


HTML_PATH = Path(__file__).parents[2] / "src" / "linen" / "server" / "static" / "index.html"


def html() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


def test_unchanged_project_poll_skips_sidebar_refreshes() -> None:
    source = html()
    load_project = source[source.index("async loadProject(id,") : source.index("async loadCompletionGate(")]

    unchanged_guard = "if (background && !changed) return false;"
    assert unchanged_guard in load_project
    assert load_project.index(unchanged_guard) < load_project.index("this.loadCompletionGate")
    assert "this.loadProject(projectId, { background: true })" in source
    assert "if (changed && this.selectedProjectId === projectId" in source


def test_background_refresh_keeps_existing_sidebar_data_visible() -> None:
    source = html()
    gate_loader = source[source.index("async loadCompletionGate(") : source.index("async loadAuditEvents(")]
    events_loader = source[source.index("async loadAuditEvents(") : source.index("async loadProjectReviews(")]
    reviews_loader = source[source.index("async loadProjectReviews(") : source.index("resetPiExecutionState(")]

    assert "if (!background) this.completionGateLoading = true;" in gate_loader
    assert "if (!background) this.completionGate = null;" in gate_loader
    assert "if (!background) {" in events_loader
    assert "if (!background) this.reviewsByFactId = {};" in reviews_loader


def test_project_poll_does_not_overlap_or_apply_a_stale_route() -> None:
    source = html()

    assert "projectPollInFlight: false" in source
    assert "if (!this.polling || this.projectPollInFlight) return;" in source
    assert "if (background && (this.selectedProjectId !== id || this.view !== 'graph')) return false;" in source
    assert "this.projectPollInFlight = false;" in source
