from pathlib import Path


def test_runs_sidebar_paginates_archive_entries_separately_from_contract_rows() -> None:
    source = Path(__file__).parents[2] / "src" / "linen" / "server" / "static" / "index.html"
    html = source.read_text(encoding="utf-8")
    assert "const offset = reset ? 0 : this.piExecutionArchiveCount;" in html
    assert "this.piExecutionArchiveCount = this.piExecutions.filter(item => !item.run_only).length;" in html
    assert 'x-show="piExecutionArchiveCount < piExecutionArchiveTotal"' in html
