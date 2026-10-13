"""Operator-registered HTTP oracles; workers cannot supply verdict programs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from .common import ContractModel


class OracleRequest(ContractModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = Field(default=None, max_length=16384)

    @field_validator("path")
    @classmethod
    def validate_local_path(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//") or "\x00" in value or "\r" in value or "\n" in value:
            raise ValueError("oracle request requires a local absolute path")
        return value


class OraclePredicate(ContractModel):
    kind: Literal["body_contains", "json_equals"]
    expected: Any
    json_pointer: str = ""
    status_codes: list[int] = Field(default_factory=lambda: [200], min_length=1, max_length=16)
    absence_status_codes: list[int] = Field(default_factory=lambda: [401, 403, 404], max_length=16)

    @model_validator(mode="after")
    def validate_predicate(self) -> "OraclePredicate":
        if any(type(code) is not int or not 100 <= code <= 599 for code in [*self.status_codes, *self.absence_status_codes]):
            raise ValueError("oracle response status must be an HTTP status code")
        if set(self.status_codes) & set(self.absence_status_codes):
            raise ValueError("capability and absence statuses must be disjoint")
        if self.kind == "body_contains" and (not isinstance(self.expected, str) or not self.expected):
            raise ValueError("body_contains requires a non-empty expected string")
        if self.kind == "json_equals" and self.json_pointer and not self.json_pointer.startswith("/"):
            raise ValueError("JSON pointer must be empty or start with /")
        return self


class OracleControl(ContractModel):
    request: OracleRequest
    target_data: dict[str, Any] = Field(default_factory=dict)


class OracleDefinition(ContractModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    source_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    image: str = Field(min_length=1)
    target_argv: list[str] = Field(min_length=1, max_length=64)
    service_port: int = Field(default=8073, ge=1024, le=65535)
    positive: OracleControl
    negative: OracleControl
    predicate: OraclePredicate
    rationale: str = Field(min_length=1, max_length=2000)
    timeout_seconds: int = Field(default=30, ge=1, le=300)

    @field_validator("image")
    @classmethod
    def validate_image(cls, value: str) -> str:
        if value.startswith("-") or "\x00" in value:
            raise ValueError("oracle image must be a local image reference")
        return value

    @field_validator("target_argv")
    @classmethod
    def validate_argv(cls, values: list[str]) -> list[str]:
        if not values or not values[0] or values[0].startswith("-") or any("\x00" in value for value in values):
            raise ValueError("oracle target requires a literal executable and argv")
        return values


class OracleBinding(ContractModel):
    project_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    oracle_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    source_generation: int = Field(ge=1)
    plan_revision: int = Field(ge=1)


class OracleCatalog(ContractModel):
    schema_version: Literal[1] = 1
    definitions: list[OracleDefinition] = Field(min_length=1, max_length=128)
    bindings: list[OracleBinding] = Field(default_factory=list, max_length=10000)

    @model_validator(mode="after")
    def validate_catalog(self) -> "OracleCatalog":
        identifiers = [definition.id for definition in self.definitions]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("oracle definition IDs must be unique")
        keys = [(binding.project_id, binding.candidate_id, binding.source_generation, binding.plan_revision) for binding in self.bindings]
        if len(set(keys)) != len(keys) or any(binding.oracle_id not in identifiers for binding in self.bindings):
            raise ValueError("oracle bindings must be unique and reference a registered definition")
        return self

    def bound_definition(self, project_id: str, candidate_id: str, source_generation: int, plan_revision: int) -> OracleDefinition:
        binding = next((item for item in self.bindings if
                        (item.project_id, item.candidate_id, item.source_generation, item.plan_revision)
                        == (project_id, candidate_id, source_generation, plan_revision)), None)
        if binding is None:
            raise ValueError("no operator-approved oracle binding for this candidate generation and plan")
        return next(definition for definition in self.definitions if definition.id == binding.oracle_id)


class HttpObservation(ContractModel):
    status_code: StrictInt = Field(ge=100, le=599)
    body: str = Field(max_length=16384)
    truncated: StrictBool


class OracleIsolation(ContractModel):
    target_image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    observer_image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    target_container: str = Field(pattern=r"^linen-review-[a-f0-9]{32}$")
    observer_container: str = Field(pattern=r"^linen-review-[a-f0-9]{32}$")
    target_network: Literal["none"]
    observer_network: Literal["target-loopback-only"]
    separate_filesystems: StrictBool
    separate_pid_namespaces: StrictBool
    source_read_only: StrictBool
    host_credentials: Literal["not_injected"]


class OracleObservation(ContractModel):
    schema_version: Literal[1] = 1
    kind: Literal["independent-oracle-observation"]
    project_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    source_generation: StrictInt = Field(ge=1)
    plan_revision: StrictInt = Field(ge=1)
    role: Literal["positive", "negative"]
    oracle_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    oracle_definition_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    checker_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    snapshot_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    raw_observation: HttpObservation
    capability_observed: StrictBool
    isolation: OracleIsolation


def judge_http_observation(predicate: OraclePredicate, observation: dict) -> bool:
    """Derive capability from raw transport fields outside the target process."""
    import json

    if set(observation) != {"status_code", "body", "truncated"} or type(observation["status_code"]) is not int or not isinstance(observation["body"], str):
        raise ValueError("invalid independent HTTP observation")
    if observation["truncated"] is not False:
        raise ValueError("truncated oracle observation cannot establish a capability")
    if observation["status_code"] not in predicate.status_codes:
        if observation["status_code"] in predicate.absence_status_codes:
            return False
        raise ValueError("unexpected target status cannot establish an oracle baseline")
    if predicate.kind == "body_contains":
        return predicate.expected in observation["body"]
    value = json.loads(observation["body"])
    if predicate.json_pointer:
        for token in predicate.json_pointer[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(value, list):
                if not token.isdigit():
                    return False
                index = int(token)
                if index >= len(value):
                    return False
                value = value[index]
            elif isinstance(value, dict) and token in value:
                value = value[token]
            else:
                return False
    return _same_json_value(value, predicate.expected)


def _same_json_value(actual: Any, expected: Any) -> bool:
    # Preserve JSON booleans versus numbers at every depth, while allowing
    # the contract's immutable dict/list subclasses.
    if isinstance(actual, dict) or isinstance(expected, dict):
        return isinstance(actual, dict) and isinstance(expected, dict) and actual.keys() == expected.keys() and all(
            _same_json_value(actual[key], expected[key]) for key in actual
        )
    if isinstance(actual, list) or isinstance(expected, list):
        return isinstance(actual, list) and isinstance(expected, list) and len(actual) == len(expected) and all(
            _same_json_value(left, right) for left, right in zip(actual, expected)
        )
    return type(actual) is type(expected) and actual == expected
