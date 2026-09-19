from pathlib import Path


HTML_PATH = Path(__file__).parents[2] / "src" / "linen" / "server" / "static" / "index.html"


def html() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


def new_audit_modal(source: str) -> str:
    start = source.index("<!-- New audit -->")
    end = source.index("<!-- Create Intent -->", start)
    return source[start:end]


def create_project_method(source: str) -> str:
    start = source.index("async createProject()")
    end = source.index("openCreateIntent()", start)
    return source[start:end]


def test_new_audit_main_path_only_asks_for_repository_and_goal() -> None:
    modal = new_audit_modal(html())

    assert ">Repository</label>" in modal
    assert "<span>Goal</span>" in modal
    assert "<span>Advanced</span>" in modal
    assert "'Start audit'" in modal
    assert "Audit profile" not in modal
    assert "Hints (optional)" not in modal
    assert "newProject.hints" not in modal


def test_advanced_preserves_explicit_audit_modes_with_scope_default() -> None:
    source = html()
    modal = new_audit_modal(source)

    assert "audit_mode: 'scope'" in source
    assert "completion_policy: 'goal_based'" in source
    assert '<span class="mb-1 block">Audit mode</span>' in modal
    assert '<option value="scope">Full audit</option>' in modal
    assert '<option value="hypothesis">Hypothesis only</option>' in modal
    assert '<option value="none">General project</option>' in modal
    assert "newProject.audit_mode === 'none' ? 'New general project' : 'New audit'" in modal


def test_project_creation_does_not_generate_or_submit_hints() -> None:
    method = create_project_method(html())

    assert "newProject.hints" not in method
    assert "body.hints" not in method
    assert "hintContents" not in method
    assert "completion_policy: this.newProject.completion_policy" in method


def test_running_project_uses_analyst_note_language_and_hint_api() -> None:
    source = html()

    for label in (
        "Notes",
        "Add analyst note",
        "No analyst notes yet",
        "Analyst note added",
    ):
        assert label in source
    assert "Add Hint" not in source
    assert "No hints yet" not in source
    assert "Hint added" not in source
    assert "`/projects/${this.selectedProjectId}/hints`" in source
