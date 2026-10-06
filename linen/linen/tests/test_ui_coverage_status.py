import json
from pathlib import Path
import shutil
import subprocess

import pytest


HTML_PATH = Path(__file__).parents[2] / "src/linen/server/static/index.html"


def view_status(evidence, *, generation=1, fact_generation=1, legacy=False):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed to execute frontend state methods")
    source = HTML_PATH.read_text(encoding="utf-8")
    status = source[source.index("projectPrimaryStatus() {"):source.index("executionStatusDotClass() {")]
    coverage = source[source.index("latestAuditSummaryFact() {"):source.index("auditSummaryFreshnessLabel() {")]
    project = {"project": {"status": "completed", "audit_mode": "scope", "source_generation": generation},
               "facts": [{"id": "summary", "type": "audit_summary", "evidence": evidence,
                          "source_generation": fact_generation, "legacy": legacy}]}
    script = "const view = {" + status + coverage + "project: " + json.dumps(project) + """,
        technicalConfirmationCandidates: () => [],
        getProducingIntent: () => ({concluded_at: '2026-10-05T00:00:00Z'}),
    }; console.log(JSON.stringify({status: view.projectPrimaryStatus(), label: view.auditCoverageLabel()}));"""
    return json.loads(subprocess.run([node, "-e", script], capture_output=True, text=True, check=True).stdout)


def test_completed_partial_audit_shows_gap_count_and_summary_action():
    result = view_status("coverage_complete: false\nresidual_gaps: 19")
    assert result["status"]["title"] == "Audit completed with coverage gaps"
    assert "19 coverage gaps" in result["status"]["detail"]
    assert result["status"]["tone"] == "attention"
    assert result["status"]["actionTarget"] == "summary"
    assert result["label"] == "19 coverage gaps"


def test_completed_covered_audit_keeps_scope_limits():
    result = view_status("coverage_complete: true\nresidual_gaps: 0")
    assert result["status"]["tone"] == "success"
    assert "not proven exhaustive" in result["status"]["detail"]


@pytest.mark.parametrize("kwargs", [{}, {"fact_generation": 2}, {"legacy": True}])
def test_missing_or_old_coverage_never_claims_complete(kwargs):
    result = view_status("" if not kwargs else "coverage_complete: true\nresidual_gaps: 0", **kwargs)
    assert result["status"]["title"] == "Audit completed · coverage unknown"
    assert result["label"] == "Coverage unknown"
