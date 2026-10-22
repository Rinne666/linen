"""The browser UI static sink audit runs as part of the regression suite.

The audit itself lives in ``ui_static_sink_check.cjs`` because it has to
execute the real browser code: the point is to show that a hostile export
document ends up as inert text, not to grep for a pattern.  This test only
runs it and checks the exit code.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("ui_static_sink_check.cjs")


@pytest.fixture(scope="module")
def node_binary() -> str:
    binary = shutil.which("node")
    if binary is None:
        pytest.skip("node is not available on this machine")
    return binary


def test_ui_static_sink_audit_passes(node_binary):
    """The report preview must never turn a hostile document into live markup."""

    completed = subprocess.run(
        [node_binary, str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, (
        f"static sink audit failed with exit code {completed.returncode}\n"
        f"{completed.stdout}\n{completed.stderr}"
    )
    report = json.loads(completed.stdout)
    assert report["ok"] is True
    assert report["failures"] == []
    assert report["checks"] > 0


def test_ui_static_sink_audit_covers_the_hostile_inputs(node_binary):
    """The audit must actually have exercised the hostile inputs."""

    completed = subprocess.run(
        [node_binary, str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    report = json.loads(completed.stdout)
    names = {entry["name"] for entry in report["results"]}
    assert {
        "img-onerror",
        "textarea-breakout",
        "entity-encoded-script",
        "bold-wrapped-payload",
        "table-line",
    } <= names
    for entry in report["results"]:
        assert "<img" not in entry["rendered"]
        assert "<script" not in entry["rendered"]
        assert "<svg" not in entry["rendered"]
