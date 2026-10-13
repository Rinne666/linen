from __future__ import annotations

import json

import jsonschema
import pytest

from linen.dispatcher.analysis.review_schema import review_response_schema
from linen.dispatcher.contracts import validate_review_payload
from linen.dispatcher.tasks.review import required_review_diagnostics


def example(schema):
    if "enum" in schema:
        return schema["enum"][0]
    if schema["type"] == "object":
        return {key: example(value) for key, value in schema["properties"].items()}
    if schema["type"] == "array":
        return []
    if schema["type"] == "boolean":
        return False
    return "independently checked source"


@pytest.mark.parametrize("profile,mode,candidate", [
    ("attestation", "devils-advocate", False),
    ("summary", "devils-advocate", False),
    ("vulnerability", "devils-advocate", True),
    ("vulnerability", "cold-verifier", True),
    ("vulnerability", "contradiction-reasoner", True),
])
def test_native_review_profiles_match_parser_and_reject_missing_diagnostics(profile, mode, candidate):
    required = required_review_diagnostics(profile, mode)
    schema = review_response_schema(required, candidate=candidate)
    jsonschema.Draft202012Validator.check_schema(schema)
    value = example(schema)
    jsonschema.validate(value, schema)
    kind, parsed = validate_review_payload(value, required_diagnostics=required)
    assert kind == "review" and all(key in parsed for key in required)
    del value[required[0]]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(value, schema)
    with pytest.raises(ValueError, match="required"):
        validate_review_payload(value, required_diagnostics=required)


def test_codex_auth_seed_is_private_ephemeral_and_not_archived(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from linen.dispatcher.config import ReviewSandboxConfig
    from linen.dispatcher.runtime import review_sandbox

    auth = tmp_path / "private-auth.json"
    content = json.dumps({"OPENAI_API_KEY": "fixture-secret"})
    auth.write_text(content)
    source = tmp_path / "source"
    source.mkdir()
    commands = []

    def run(argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(returncode=0, stdout="sha256:" + "a" * 64, stderr="")

    class Process:
        def __init__(self, *args, **kwargs): pass
        def start(self): pass
        def kill(self): pass

    monkeypatch.setattr(review_sandbox.shutil, "which", lambda _: "docker")
    monkeypatch.setattr(review_sandbox.subprocess, "run", run)
    monkeypatch.setattr(review_sandbox, "LocalProcess", Process)
    cfg = ReviewSandboxConfig(enabled=True, image="fixture", codex_auth_file=str(auth))
    process = review_sandbox.DockerReviewProcess(cfg, source, {"id": "frozen", "files": {}},
                                                tmp_path / "run", ["codex", "exec", "--json"], {}, 10)
    process.start()
    seed = review_sandbox.Path(process.auth_seed.name) / "auth.json"
    assert seed.read_text() == content
    assert seed.parent.stat().st_mode & 0o777 == 0o700
    assert all("fixture-secret" not in str(command) for command in commands)
    assert all("fixture-secret" not in path.read_text() for path in process.run_dir.rglob("*") if path.is_file())
    assert auth.read_text() == content
    process.kill()
    assert not seed.exists() and process.auth_seed is None


def test_isolated_codex_argv_handles_root_options_and_is_idempotent():
    from linen.dispatcher.runtime.review_sandbox import isolated_review_argv
    argv = ["codex", "--ask-for-approval", "never", "exec", "--sandbox", "read-only", "--", "prompt"]
    prepared = isolated_review_argv(argv)
    assert prepared[4] == "--skip-git-repo-check"
    assert isolated_review_argv(prepared) == prepared and "--skip-git-repo-check" not in argv
