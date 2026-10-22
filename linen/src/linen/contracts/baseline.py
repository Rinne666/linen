"""The trusted historical baseline contracts (CF-S2-B1).

A prior status is only worth storing when the history it was derived from can
be found again and checked.  A free-text ``lookup_ref`` cannot do that: a path
can be rewritten, and a sentence can be retyped.  These contracts therefore
describe a *structured* reference body, and the reference itself is the
digest of that body (D-037).

The chain the contracts describe is the one the PM froze in D-036:

```text
external run directory
    -> controlled import
    -> format and origin verification
    -> immutable registration
    -> frozen lineage manifest
    -> trusted resolver
```

Nothing here decides whether a prior run is *compatible*: that is the
resolver's job in CF-S2-B2.  What these contracts do decide is what has to be
written down before a resolver is allowed to claim that a history does not
exist, and what a source identity has to look like before anyone may call it
verified.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Mapping

from pydantic import Field, field_validator, model_validator

from .common import ContractModel, cf_canonical_json, cf_payload_digest, validate_sha256

#: The versioned prefix of an immutable reference (D-031 in PM v2.1).
CF_REFERENCE_PREFIX = "cf-ref-v1:"

#: The domain separation of a validation authentication envelope (D-058).
#:
#: The MAC of one receipt may never be replayed for another purpose, another
#: project or another source, so the bytes it covers always carry this
#: prefix.
VALIDATION_AUTH_DOMAIN = "linen:baseline-ledger-validation:v1"

#: A git object name, in the shape git itself writes.
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

#: The kinds of source identity a historical run can claim.
BaselineIdentityKind = Literal["git_commit", "frozen_digest", "unverified"]

#: The kinds of validation a controlled receipt can carry.
BaselineValidationKind = Literal["cloudflare_coverage_ledger"]

#: The runner that actually executed the pinned upstream validator.
#:
#: ``native`` is the upstream CLI itself.  ``windows_runner`` is the
#: linen-authored shim that restores the two POSIX open flags Node on win32
#: does not expose: it reaches the same schema verdict, but it does not have
#: the same kernel-level file-open guarantee (D-051).
BaselineValidatorRunner = Literal["native", "windows_runner"]

#: The kinds of lineage scope a manifest can declare.
BaselineScopeKind = Literal["declared_predecessor_lineage", "lineage_root"]

#: How complete a declared history scope is.
BaselineCompleteness = Literal["complete", "incomplete"]


def encode_reference(body: Mapping[str, Any]) -> str:
    """The immutable reference of a structured reference body.

    The reference is the digest of the canonical JSON of the body, so it
    cannot be forged without changing the body, and the body can be found
    again by its digest.  The string alone is not evidence: the body has to
    be readable and its digest has to be re-verified (PM v2.1, "强制要求").
    """

    return CF_REFERENCE_PREFIX + cf_payload_digest(body)


def reference_digest(reference: str) -> str:
    """The digest part of a reference, or a clear failure.

    A reference that merely *looks* like one is not a reference: the body
    has to exist and its digest has to match, and that can only be checked
    against the stored body.
    """

    if not reference.startswith(CF_REFERENCE_PREFIX):
        raise ValueError(
            f"a baseline reference must start with {CF_REFERENCE_PREFIX!r}"
        )
    digest = reference[len(CF_REFERENCE_PREFIX):]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("a baseline reference must carry a 64 hex digit digest")
    return digest


class BaselineSourceIdentity(ContractModel):
    """What is known about the source a historical run was produced from.

    A 40 hex string only proves that something *looks* like a git object
    name; it does not prove that the audited worktree was that commit.  The
    importer therefore never promotes a ``source_ref`` to a verified identity
    on its own: it records the raw text and leaves the verification to an
    explicit, separate act.

    ``verified`` may only be true for an identity whose kind carries a real
    anchor - a git commit or a frozen source digest.
    """

    kind: BaselineIdentityKind
    origin: str = Field(min_length=1, max_length=1024)
    revision: str | None = Field(default=None, max_length=64)
    digest: str | None = Field(default=None)
    raw: str | None = Field(default=None, max_length=4096)
    verified: bool = False
    notes: str = Field(default="", max_length=4096)

    @field_validator("origin", "notes")
    @classmethod
    def _strip_text(cls, value: str) -> str:
        return value.strip()

    @field_validator("digest")
    @classmethod
    def _validate_digest(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_sha256(value)

    @field_validator("revision")
    @classmethod
    def _validate_revision(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _GIT_COMMIT_RE.fullmatch(value):
            raise ValueError("a git revision must be a 40 hex digit commit name")
        return value

    @model_validator(mode="after")
    def _validate_shape(self) -> "BaselineSourceIdentity":
        if self.kind == "git_commit":
            if not self.revision:
                raise ValueError(
                    "a git commit identity requires the commit it claims"
                )
        elif self.kind == "frozen_digest":
            if not self.digest:
                raise ValueError(
                    "a non-git source requires a frozen source digest"
                )
        else:  # unverified
            if self.verified:
                raise ValueError(
                    "an unverified source identity cannot claim to be verified"
                )
            if not self.raw:
                raise ValueError(
                    "an unverified source identity must keep the text it was "
                    "derived from"
                )
        if self.verified and self.kind == "unverified":
            raise ValueError("an unverified identity is never verified")
        return self

    @classmethod
    def unverified_from_ref(cls, *, origin: str, raw: str) -> "BaselineSourceIdentity":
        """The identity of a ``source_ref`` that has not been verified.

        A leading commit name is recorded as a *candidate*, but the identity
        stays unverified: a regex that matched is not a verification.
        """

        text = raw.strip()
        candidate = None
        head = text.split(" ", 1)[0].strip()
        if _GIT_COMMIT_RE.fullmatch(head):
            candidate = head
        return cls(
            kind="unverified",
            origin=origin.strip(),
            revision=candidate,
            raw=text,
            verified=False,
        )


class BaselineSourceRecord(ContractModel):
    """One registered historical source.

    The record names the artifacts it was built from by their content
    digests, so a later reader can check that the very same bytes are still
    what the record was derived from.
    """

    schema_version: int = 1
    project_id: str = Field(min_length=1, max_length=2048)
    source_ref: str = Field(min_length=1, max_length=1024)
    ledger_sha256: str
    metadata_sha256: str
    source_identity: BaselineSourceIdentity
    unit_count: int = Field(default=0, ge=0)
    prior_status_counts: dict[str, int] = Field(default_factory=dict)
    ledger_path: str = Field(default="", max_length=2048)
    metadata_path: str = Field(default="", max_length=2048)
    notes: str = Field(default="", max_length=4096)

    @field_validator("ledger_sha256", "metadata_sha256")
    @classmethod
    def _validate_digests(cls, value: str) -> str:
        return validate_sha256(value)

    @field_validator("project_id", "source_ref")
    @classmethod
    def _strip_required(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value

    @model_validator(mode="after")
    def _validate_counts(self) -> "BaselineSourceRecord":
        for status, count in self.prior_status_counts.items():
            if count < 0:
                raise ValueError("a prior status count cannot be negative")
        return self


class BaselineManifestMember(ContractModel):
    """One historical source that belongs to a declared lineage scope."""

    source_ref: str = Field(min_length=1, max_length=1024)
    ledger_sha256: str
    metadata_sha256: str

    @field_validator("ledger_sha256", "metadata_sha256")
    @classmethod
    def _validate_digests(cls, value: str) -> str:
        return validate_sha256(value)

    @field_validator("source_ref")
    @classmethod
    def _strip_source_ref(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("source_ref must not be empty")
        return value


class BaselineLineageManifest(ContractModel):
    """The frozen inventory of the history a baseline may be derived from.

    ``none`` is a statement about a *closed* scope: every source that the
    protocol declared to be comparable has been registered and searched.  A
    manifest that still has unprocessed members is not a closed scope, so it
    can never be the basis of a negative conclusion (D-037).

    A first generation run has no predecessor.  It therefore declares a
    ``lineage_root`` scope with no members - an explicit statement about the
    history of the project, not the observation that a query came back empty.
    """

    schema_version: int = 1
    project_id: str = Field(min_length=1, max_length=2048)
    scope_kind: BaselineScopeKind = "declared_predecessor_lineage"
    members: list[BaselineManifestMember] = Field(default_factory=list, max_length=1000)
    unprocessed: list[str] = Field(default_factory=list, max_length=1000)
    completeness: BaselineCompleteness = "incomplete"
    notes: str = Field(default="", max_length=4096)

    @field_validator("project_id")
    @classmethod
    def _strip_project(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("project_id must not be empty")
        return value

    @model_validator(mode="after")
    def _validate_scope(self) -> "BaselineLineageManifest":
        if self.scope_kind == "lineage_root" and self.members:
            raise ValueError(
                "a lineage root declares that there is no predecessor, so it "
                "cannot list any member"
            )
        if self.completeness == "complete" and self.unprocessed:
            raise ValueError(
                "a complete history scope cannot have unprocessed members"
            )
        seen: set[str] = set()
        for member in self.members:
            if member.source_ref in seen:
                raise ValueError(
                    f"source {member.source_ref!r} appears more than once in "
                    "the manifest"
                )
            seen.add(member.source_ref)
        return self

    @property
    def closed(self) -> bool:
        """Whether this scope is closed enough to support a negative claim."""

        return self.completeness == "complete" and not self.unprocessed

    def body(self) -> dict[str, Any]:
        """The content this manifest is referenced by."""

        return self.model_dump(mode="json")

    def reference(self) -> str:
        """The immutable reference of this manifest."""

        return encode_reference(self.body())


class LedgerValidatorIdentity(ContractModel):
    """Which validator actually ran, and on what.

    The identity is part of the evidence: a receipt produced by a different
    validator file, or by a different upstream commit, is not the same proof
    (D-043).
    """

    upstream_commit: str = Field(min_length=1, max_length=64)
    validator_sha256: str
    runner: BaselineValidatorRunner
    platform: str = Field(min_length=1, max_length=64)

    @field_validator("validator_sha256")
    @classmethod
    def _validate_digest(cls, value: str) -> str:
        return validate_sha256(value)


class LedgerValidationResult(ContractModel):
    """What the pinned validator decided about one document."""

    valid: bool
    record_count: int = Field(default=0, ge=0)
    errors: list[str] = Field(default_factory=list, max_length=200)


def validation_auth_mac_input(
    *,
    receipt_sha256: str,
    project_id: str,
    source_ref: str,
    ledger_sha256: str,
    metadata_sha256: str,
) -> bytes:
    """The exact bytes a validation authentication MAC covers.

    The input is domain separated and canonical, so the same facts always
    produce the same bytes - and the MAC of one receipt can never be
    replayed for another project, another source or another set of bytes
    (D-058).
    """

    body = cf_canonical_json(
        {
            "ledger_sha256": ledger_sha256,
            "metadata_sha256": metadata_sha256,
            "project_id": project_id,
            "receipt_sha256": receipt_sha256,
            "source_ref": source_ref,
        }
    )
    return VALIDATION_AUTH_DOMAIN.encode("utf-8") + b"\x00" + body.encode("utf-8")


class LedgerValidationAuth(ContractModel):
    """The authentication envelope of one validation receipt (D-058).

    A receipt's own digest proves that its body was not changed.  It does
    *not* prove that anybody was allowed to issue it: anybody who can
    construct JSON can construct a body that matches its own digest.

    This envelope is the second half of the answer.  It carries a MAC over
    the receipt and the source it is about, made with a key that only the
    controlled offline flow holds, and it is what makes a registered receipt
    trustworthy.  The envelope never changes the receipt: the receipt keeps
    its own digest, and the relationship between the two is recorded
    separately (D-058, D-059).
    """

    auth_version: int = 1
    key_id: str = Field(min_length=1, max_length=128)
    receipt_sha256: str
    project_id: str = Field(min_length=1, max_length=2048)
    source_ref: str = Field(min_length=1, max_length=1024)
    ledger_sha256: str
    metadata_sha256: str
    mac: str = Field(min_length=64, max_length=64)

    @field_validator("receipt_sha256", "ledger_sha256", "metadata_sha256")
    @classmethod
    def _validate_digests(cls, value: str) -> str:
        return validate_sha256(value)

    @field_validator("mac")
    @classmethod
    def _validate_mac(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("the mac must be 64 lower case hex digits")
        return value

    @field_validator("project_id", "source_ref", "key_id")
    @classmethod
    def _strip_required(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value

    def mac_input(self) -> bytes:
        """The bytes this envelope's MAC covers."""

        return validation_auth_mac_input(
            receipt_sha256=self.receipt_sha256,
            project_id=self.project_id,
            source_ref=self.source_ref,
            ledger_sha256=self.ledger_sha256,
            metadata_sha256=self.metadata_sha256,
        )


class LedgerValidationReceipt(ContractModel):
    """A versioned proof that one exact ledger document passed the validator.

    A receipt is only worth what it binds, so it names the bytes it was
    produced from, the validator that produced it, the result it reached and
    the source it is about - and it carries a digest of its own body, so a
    later reader can tell whether it was altered.

    What a receipt proves is a *format* decision.  It says nothing about the
    source identity of the audited worktree: that is a separate attestation
    (CF-S2-B2).  The two must never be merged (D-043, D-051).
    """

    schema_version: int = 1
    validation_kind: BaselineValidationKind = "cloudflare_coverage_ledger"
    ledger_sha256: str
    validator: LedgerValidatorIdentity
    result: LedgerValidationResult
    project_id: str = Field(min_length=1, max_length=2048)
    source_ref: str = Field(min_length=1, max_length=1024)
    metadata_sha256: str
    issued_by: str = Field(min_length=1, max_length=2048)
    issued_at: str = Field(min_length=1, max_length=64)
    receipt_sha256: str

    @field_validator("ledger_sha256", "metadata_sha256", "receipt_sha256")
    @classmethod
    def _validate_digests(cls, value: str) -> str:
        return validate_sha256(value)

    @field_validator("project_id", "source_ref")
    @classmethod
    def _strip_required(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value

    def body(self) -> dict[str, Any]:
        """The content this receipt is sealed by."""

        payload = self.model_dump(mode="json")
        payload.pop("receipt_sha256", None)
        return payload

    def sealed(self) -> bool:
        """Whether the receipt still matches its own digest."""

        return cf_payload_digest(self.body()) == self.receipt_sha256

    @classmethod
    def issue(cls, **fields: Any) -> "LedgerValidationReceipt":
        """Seal a receipt over the fields that describe one validation."""

        payload = {key: value for key, value in fields.items() if key != "receipt_sha256"}
        digest = cf_payload_digest(cls(**payload, receipt_sha256="0" * 64).body())
        return cls(**payload, receipt_sha256=digest)
