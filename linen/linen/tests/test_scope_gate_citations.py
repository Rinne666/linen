"""Citation validation: whitespace canonicalization + actionable errors."""

import pytest

from linen.contracts.reason import ReasonWait
from linen.dispatcher.analysis import scope_gate
from linen.dispatcher.analysis.artifacts import digest


FILES = {
    "local/README.md": (
        "# BenchmarkPython local subset\n"
        "\n"
        "See SECURITY.md for evaluation scope.\n"
    ),
}


@pytest.fixture()
def citation_env(tmp_path):
    source = tmp_path / "snapshot"
    (source / "local").mkdir(parents=True)
    (source / "local" / "README.md").write_text(FILES["local/README.md"])
    manifest = {
        "snapshot": {
            "files": {
                name: digest(data.encode()) for name, data in FILES.items()
            },
        },
        "sources": [
            {"id": "policy-002", "status": "collected",
             "snapshot_file": "local/README.md"},
        ],
    }
    return source, manifest


def _citation(line, quote):
    return {
        "id": "c1", "source_id": "policy-002",
        "file": "local/README.md", "line": line, "quote": quote,
    }


def test_trailing_whitespace_is_canonicalized(citation_env):
    source, manifest = citation_env
    result = scope_gate._canonical_citations(
        [_citation(3, "See SECURITY.md for evaluation scope.  ")], source, manifest,
    )
    assert result[0]["line"] == 3


def test_indentation_drift_is_canonicalized_multiline(citation_env):
    source, manifest = citation_env
    result = scope_gate._canonical_citations(
        [_citation(1, "  # BenchmarkPython local subset\n")], source, manifest,
    )
    assert result[0]["line"] == 1


def test_wrong_line_reports_frozen_content(citation_env):
    source, manifest = citation_env
    with pytest.raises(ValueError) as excinfo:
        scope_gate._canonical_citations(
            [_citation(2, "See SECURITY.md for evaluation scope.")],
            source, manifest,
        )
    message = str(excinfo.value)
    assert "local/README.md:2" in message
    # The error names the frozen line so the model can self-correct.
    assert "frozen line 2 reads" in message


def test_non_whitespace_drift_still_rejected(citation_env):
    source, manifest = citation_env
    with pytest.raises(ValueError) as excinfo:
        scope_gate._canonical_citations(
            [_citation(3, "See SECURITY.md for evaluation scope!")],
            source, manifest,
        )
    assert "does not match frozen source" in str(excinfo.value)


def test_reason_wait_allows_detailed_blockers():
    wait = ReasonWait(intent_ids=["i003"], reason="x" * 3900)
    assert len(wait.reason) == 3900
    with pytest.raises(Exception):
        ReasonWait(intent_ids=["i003"], reason="x" * 4001)
