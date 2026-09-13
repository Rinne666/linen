from __future__ import annotations

from pathlib import Path

import pytest

from linen.dispatcher.config import LocalConfig
from linen.dispatcher.runtime.backend import LocalBackend


def test_local_backend_writes_absolute_prompt_snapshot(tmp_path: Path) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path / "work")))
    target = tmp_path / "linen-prompts" / "reason" / "graph.yaml"

    backend.write_text_file(str(tmp_path / "work"), str(target), "facts:\n- id: f001\n")

    assert target.read_text() == "facts:\n- id: f001\n"


@pytest.mark.parametrize("path", ["relative.txt", "nested/graph.yaml"])
def test_local_backend_rejects_relative_prompt_paths(tmp_path: Path, path: str) -> None:
    backend = LocalBackend(LocalConfig(workspace_root=str(tmp_path)))
    with pytest.raises(ValueError, match="absolute"):
        backend.write_text_file(str(tmp_path), path, "content")
