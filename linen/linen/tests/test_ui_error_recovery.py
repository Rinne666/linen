from pathlib import Path


HTML_PATH = Path(__file__).parents[2] / "src" / "linen" / "server" / "static" / "index.html"


def html() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


def test_project_error_is_visible_without_selecting_an_intent() -> None:
    source = html()
    status_start = source.index('aria-label="Project execution status"')
    workspace_start = source.index('id="graphLayout"', status_start)
    error_surface = source[status_start:workspace_start]

    assert 'primaryProjectError()' in error_surface
    assert 'role="alert"' in error_surface
    assert "Needs attention" in error_surface
    assert "projectErrorMessage(primaryProjectError())" in error_surface
    assert "projectErrorRecovery(primaryProjectError())" in error_surface


def test_project_error_allows_direct_retry_and_prevents_double_submit() -> None:
    source = html()

    assert '@click="retryIntentError(primaryProjectError())"' in source
    assert "retryingIntentId === primaryProjectError().intent_id ? 'Retrying…' : 'Retry now'" in source
    assert "if (!this.canRetryIntentError(error) || this.retryingIntentId) return;" in source
    assert "`/projects/${this.selectedProjectId}/intents/${error.intent_id}/retry`" in source
    assert "{ actor: this.actorName() }" in source
    assert "await this.loadProject(this.selectedProjectId);" in source


def test_known_provider_error_uses_user_facing_recovery_copy() -> None:
    source = html()

    assert "provider_quota_exhausted: 'Model provider quota exhausted'" in source
    assert "Restore the model provider quota, then retry this work item." in source
    assert "Automatic retry was deferred until" in source
    assert "error.remediation || 'Correct the problem, then retry this work item.'" in source


def test_removed_scanner_stages_are_not_presented_as_runnable_tools() -> None:
    source = html()

    assert "visibleAuditStages()" in source
    assert "isRetiredToolStage(stage)" in source
    assert "'semgrep', 'spotbugs-findsecbugs', 'osv-scanner', 'gitleaks', 'trivy'" in source
    assert "tools on demand" not in source
    assert ">Optional</span>" in source
