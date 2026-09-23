from pathlib import Path


HTML_PATH = Path(__file__).parents[2] / "src" / "linen" / "server" / "static" / "index.html"


def html() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


def test_project_error_is_visible_without_selecting_an_intent() -> None:
    source = html()
    error_surface = source[source.index("<!-- Blocked work and execution failures -->"):]

    assert "unresolvedProjectErrors()" in error_surface
    assert 'x-show="sideTab === \'blocked\'"' in error_surface
    assert "projectErrorReasonLabel(error)" in error_surface
    assert "projectErrorTitle(error)" in error_surface
    assert "projectErrorRecovery(error)" in error_surface


def test_project_error_allows_direct_retry_and_prevents_double_submit() -> None:
    source = html()

    assert '@click="retryIntentError(error)"' in source
    assert "retryingIntentId === error.intent_id ? 'Retrying…' : 'Retry now'" in source
    assert "if (!this.canRetryIntentError(error) || this.retryingIntentId) return;" in source
    assert "`/projects/${this.selectedProjectId}/intents/${error.intent_id}/retry`" in source
    assert "{ actor: this.actorName() }" in source
    assert "await this.loadProject(this.selectedProjectId);" in source


def test_known_provider_error_uses_user_facing_recovery_copy() -> None:
    source = html()

    assert "provider_quota_exhausted: 'Model provider quota exhausted'" in source
    assert "Restore the model provider quota, then retry this work item." in source
    assert "Automatic retry was deferred until" in source
    assert "if (error.remediation) return error.remediation;" in source
    assert "This failure is considered temporary; retry after the backoff window." in source


def test_removed_scanner_stages_are_not_presented_as_runnable_tools() -> None:
    source = html()

    assert "visibleAuditStages()" in source
    assert "isRetiredToolStage(stage)" in source
    assert "'semgrep', 'spotbugs-findsecbugs', 'osv-scanner', 'gitleaks', 'trivy'" in source
    assert "tools on demand" not in source
    assert ">Optional</span>" in source
