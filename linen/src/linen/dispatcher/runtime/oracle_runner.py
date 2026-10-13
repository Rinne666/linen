"""Registered target and observer run in separate disposable environments."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from linen.contracts.oracle import OracleDefinition, OracleObservation, judge_http_observation
from linen.dispatcher.config import ReviewSandboxConfig
from linen.dispatcher.runtime.process import ProcessResult
from linen.dispatcher.runtime.review_sandbox import DockerReviewProcess


def oracle_checker_digest() -> str:
    from linen.contracts import oracle

    parts = [Path(oracle.__file__).read_bytes(), Path(__file__).read_bytes(),
             Path(__file__).with_name("oracle_observer.py").read_bytes(),
             Path(__file__).with_name("review_sandbox.py").read_bytes()]
    return hashlib.sha256(b"\x00".join(parts)).hexdigest()


class RegisteredOracleProcess:
    """ExecProcess adapter; no model-generated program or verdict is accepted."""

    def __init__(self, definition: OracleDefinition, role: str, source: Path, snapshot: dict, root: Path,
                 *, project_id: str, candidate_id: str, run_id: str, source_generation: int, plan_revision: int,
                 timeout_seconds: int):
        if role not in {"positive", "negative"}:
            raise ValueError("oracle role must be positive or negative")
        if snapshot.get("id") != definition.source_digest:
            raise ValueError("registered oracle does not bind this frozen source")
        self.definition, self.role, self.source, self.snapshot, self.root = definition, role, source, snapshot, root
        self.binding = dict(project_id=project_id, candidate_id=candidate_id, run_id=run_id,
                            source_generation=source_generation, plan_revision=plan_revision)
        self.timeout = min(definition.timeout_seconds, timeout_seconds)
        self.target: DockerReviewProcess | None = None
        self.observer: DockerReviewProcess | None = None
        self.cancelled: str | None = None
        self.observation: dict | None = None
        self.receipt: dict | None = None

    def start(self) -> None:
        self.root.mkdir(parents=True, exist_ok=False)
        control = getattr(self.definition, self.role)
        config = ReviewSandboxConfig(enabled=True, image=self.definition.image, network="none", env_allowlist=[], memory="512m", cpus=1)
        target_data = json.dumps(control.target_data, sort_keys=True).encode()
        self.target = DockerReviewProcess(config, self.source, self.snapshot, self.root / "target",
                                         self.definition.target_argv, {}, self.timeout,
                                         {"oracle_case.json": target_data})
        try:
            self.target.start()
            if self.cancelled:
                self.target.cancel(self.cancelled)
                return
            # Resolve the tag once, then use the same immutable image for the
            # observer. It receives no target source, HOME, history or secrets.
            config = config.model_copy(update={"image": self.target.image_id})
            empty_source = self.root / "observer-empty"
            empty_source.mkdir()
            observer_case = {"service_port": self.definition.service_port, "timeout_seconds": self.timeout,
                             "request": control.request.model_dump(mode="json")}
            self.observer = DockerReviewProcess(
                config, empty_source, {"id": "observer-no-target-source", "files": {}}, self.root / "observer",
                ["python3", "-I", "/input/oracle_observer.py", "/input/oracle_case.json"], {}, self.timeout,
                {"oracle_observer.py": Path(__file__).with_name("oracle_observer.py").read_bytes(),
                 "oracle_case.json": json.dumps(observer_case).encode()}, network_container=self.target.name,
            )
            self.observer.start()
        except BaseException:
            self.kill()
            raise

    def communicate(self, timeout: float | None) -> ProcessResult:
        if self.cancelled:
            return ProcessResult(130, "", "", cancelled=True, cancel_reason=self.cancelled)
        if self.observer is None or self.target is None:
            raise RuntimeError("registered oracle has not started")
        try:
            result = self.observer.communicate(timeout)
            if result.returncode != 0 or result.timed_out or result.cancelled:
                return result
            self.observation = json.loads(result.stdout)
            capability = judge_http_observation(self.definition.predicate, self.observation)
            self.receipt = {
                "schema_version": 1, "kind": "independent-oracle-observation", **self.binding,
                "role": self.role, "oracle_id": self.definition.id,
                "oracle_definition_sha256": self.definition.canonical_digest(),
                "checker_sha256": oracle_checker_digest(), "snapshot_id": self.snapshot["id"],
                "raw_observation": self.observation, "capability_observed": capability,
                "isolation": {"target_image_id": self.target.image_id, "observer_image_id": self.observer.image_id,
                              "target_container": self.target.name, "observer_container": self.observer.name,
                              "target_network": "none", "observer_network": "target-loopback-only",
                              "separate_filesystems": True, "separate_pid_namespaces": True,
                              "source_read_only": True, "host_credentials": "not_injected"},
            }
            self.receipt = OracleObservation.model_validate(self.receipt).model_dump(mode="json")
            encoded = json.dumps(self.receipt, sort_keys=True)
            (self.root / "observation.json").write_text(encoded + "\n")
            return ProcessResult(0, encoded, result.stderr)
        except (ValueError, TypeError, KeyError) as exc:
            return ProcessResult(1, "", f"IndependentOracleInvalidObservation: {exc}")
        finally:
            self.target.kill()

    def cancel(self, reason: str) -> None:
        self.cancelled = self.cancelled or reason
        if self.observer is not None:
            self.observer.cancel(self.cancelled)
        if self.target is not None:
            self.target.cancel(self.cancelled)

    def kill(self) -> None:
        if self.observer is not None and self.observer.created:
            self.observer.kill()
        if self.target is not None and self.target.created:
            self.target.kill()
