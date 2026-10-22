"""The trusted issuance of validation receipts (CF-S2-B1 P1-C, D-058).

A validation receipt proves that the pinned upstream validator accepted one
exact document.  It does not prove that anybody was *allowed* to issue it: its
own digest only shows that its body was not changed, and anybody who can
construct JSON can construct a body that matches its own digest.  A receipt
that was never issued by the controlled flow therefore looks exactly like one
that was - unless the two are told apart.

This module is that difference.  A receipt becomes trustworthy when it carries
an **authentication envelope**: a MAC over the receipt and the source it is
about, made with a key that only the controlled offline flow holds.  The
server never issues an envelope; it only verifies one, and it records the
relationship in its own append-only table without ever touching the receipt.

What this does and does not prove (D-058):

* the MAC proves that the holder of the shared key made the envelope, in the
  controlled flow - it does not prove *which* person made it, and it is not a
  non-repudiable signature;
* the key never reaches the database, the repository, a prompt, a log line,
  an error message or the audit graph - only its identifier is recorded;
* a deployment without a configured key fails closed: nothing is trusted,
  because nothing can be proven.

The envelope is a proof about a *receipt*.  It is not the source identity
attestation of CF-S2-B2, and it must never be mistaken for one (D-059).
"""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
from dataclasses import dataclass
from hashlib import sha256

from linen.contracts.baseline import (
    LedgerValidationAuth,
    LedgerValidationReceipt,
    validation_auth_mac_input,
)
from linen.contracts.common import cf_canonical_json, cf_payload_digest
from linen.server.services import utcnow

#: The environment variable the operator injects the keys with.
#:
#: The value is a JSON object: ``{"baseline-validator-key-1": "<hex>"}``.
#: The key bytes never leave the process that reads this variable.
VALIDATION_KEYS_ENV = "LINEN_BASELINE_VALIDATION_KEYS"

#: The key identifier used when a deployment configured exactly one key.
DEFAULT_KEY_ID = "baseline-validator-key-1"


class BaselineAuthRejected(ValueError):
    """The authentication envelope is not acceptable."""


@dataclass(frozen=True)
class ValidationAuthKey:
    """One configured key: its identifier and its bytes."""

    key_id: str
    secret: bytes


def configured_validation_keys() -> dict[str, ValidationAuthKey]:
    """The keys the operator configured, keyed by their identifier.

    A missing, malformed or empty configuration yields no keys at all, and
    no keys means every trust decision fails closed.
    """

    raw = os.environ.get(VALIDATION_KEYS_ENV, "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    keys: dict[str, ValidationAuthKey] = {}
    for key_id, secret in parsed.items():
        if not isinstance(key_id, str) or not key_id.strip():
            continue
        if not isinstance(secret, str):
            continue
        try:
            material = bytes.fromhex(secret.strip())
        except ValueError:
            continue
        if not material:
            continue
        keys[key_id.strip()] = ValidationAuthKey(key_id=key_id.strip(), secret=material)
    return keys


def signing_key(key_id: str | None = None) -> ValidationAuthKey | None:
    """The key an envelope may be signed with.

    A deployment that configured exactly one key may leave the identifier
    out.  A deployment that configured several has to say which key it
    signs with, and a deployment that configured none has no key at all -
    which means it cannot issue a trusted envelope, and therefore cannot
    produce a trusted validation.
    """

    keys = configured_validation_keys()
    if not keys:
        return None
    if key_id is None:
        if len(keys) == 1:
            return next(iter(keys.values()))
        return None
    return keys.get(key_id.strip())


def sign_validation_auth(
    *, receipt: LedgerValidationReceipt, key: ValidationAuthKey
) -> LedgerValidationAuth:
    """The authentication envelope of one receipt, made with one key."""

    payload = validation_auth_mac_input(
        receipt_sha256=receipt.receipt_sha256,
        project_id=receipt.project_id,
        source_ref=receipt.source_ref,
        ledger_sha256=receipt.ledger_sha256,
        metadata_sha256=receipt.metadata_sha256,
    )
    mac = hmac.new(key.secret, payload, sha256).hexdigest()
    return LedgerValidationAuth(
        auth_version=1,
        key_id=key.key_id,
        receipt_sha256=receipt.receipt_sha256,
        project_id=receipt.project_id,
        source_ref=receipt.source_ref,
        ledger_sha256=receipt.ledger_sha256,
        metadata_sha256=receipt.metadata_sha256,
        mac=mac,
    )


def verify_auth_mac(*, envelope: LedgerValidationAuth, key: ValidationAuthKey) -> bool:
    """Whether the envelope's MAC was made with this key."""

    expected = hmac.new(key.secret, envelope.mac_input(), sha256).hexdigest()
    return hmac.compare_digest(expected, envelope.mac)


def issue_trusted_authentication(
    *, receipt: LedgerValidationReceipt, key_id: str | None = None
) -> LedgerValidationAuth | None:
    """The authentication envelope of one receipt, or nothing.

    A deployment without a configured key has no way to issue a trusted
    envelope, and therefore no way to produce a trusted validation.  That is
    the fail closed case, and it is reported as *no envelope* rather than as
    an envelope that happens to be missing later.
    """

    key = signing_key(key_id)
    if key is None:
        return None
    return sign_validation_auth(receipt=receipt, key=key)


def register_validation_auth(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    receipt: LedgerValidationReceipt,
    envelope: LedgerValidationAuth,
) -> str:
    """Record one authentication envelope, append-only.

    The envelope has to be about *this* receipt - same digest, same project,
    same source, same bytes - and its MAC has to be made with a key the
    deployment trusts.  Registering the same envelope twice does nothing;
    registering a *different* envelope for the same receipt and key is a
    conflict and is refused, because two envelopes for one receipt would
    make the record ambiguous.
    """

    if envelope.receipt_sha256 != receipt.receipt_sha256:
        raise BaselineAuthRejected(
            "the authentication envelope is about another receipt"
        )
    if envelope.project_id != project_id or envelope.project_id != receipt.project_id:
        raise BaselineAuthRejected(
            "the authentication envelope is about another project"
        )
    if envelope.source_ref != receipt.source_ref:
        raise BaselineAuthRejected(
            "the authentication envelope is about another source"
        )
    if envelope.ledger_sha256 != receipt.ledger_sha256:
        raise BaselineAuthRejected(
            "the authentication envelope is about other ledger bytes"
        )
    if envelope.metadata_sha256 != receipt.metadata_sha256:
        raise BaselineAuthRejected(
            "the authentication envelope is about other metadata bytes"
        )

    key = configured_validation_keys().get(envelope.key_id)
    if key is None:
        raise BaselineAuthRejected(
            "the authentication envelope names a key this deployment does not trust"
        )
    if not verify_auth_mac(envelope=envelope, key=key):
        raise BaselineAuthRejected(
            "the authentication envelope does not carry a valid mac"
        )

    registered = conn.execute(
        "SELECT payload_sha256 FROM coverage_ledger_validations WHERE project_id = ? "
        "AND payload_sha256 = ?",
        (project_id, receipt.receipt_sha256),
    ).fetchone()
    if registered is None:
        raise BaselineAuthRejected(
            "the receipt this envelope authenticates is not registered"
        )

    body = envelope.model_dump(mode="json")
    digest = cf_payload_digest(body)
    existing = conn.execute(
        "SELECT payload_sha256 FROM coverage_ledger_validation_auths "
        "WHERE project_id = ? AND receipt_sha256 = ? AND key_id = ?",
        (project_id, receipt.receipt_sha256, envelope.key_id),
    ).fetchone()
    if existing is not None:
        if str(existing["payload_sha256"]) != digest:
            raise BaselineAuthRejected(
                "another authentication envelope is already registered for this "
                "receipt and key"
            )
        return digest

    conn.execute(
        "INSERT INTO coverage_ledger_validation_auths (project_id, receipt_sha256, "
        "key_id, payload_json, payload_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            project_id,
            receipt.receipt_sha256,
            envelope.key_id,
            cf_canonical_json(body),
            digest,
            utcnow(),
        ),
    )
    return digest


def trusted_validation_auth(
    conn: sqlite3.Connection,
    *,
    project_id: str,
    receipt: LedgerValidationReceipt,
) -> LedgerValidationAuth:
    """The envelope that makes this receipt trustworthy.

    An envelope only counts when its key is still configured and its MAC
    verifies.  An envelope that names an unknown key, or whose MAC does not
    verify, proves nothing - and a receipt without a valid envelope proves
    nothing either, so this fails closed.
    """

    rows = conn.execute(
        "SELECT payload_json FROM coverage_ledger_validation_auths "
        "WHERE project_id = ? AND receipt_sha256 = ? ORDER BY auth_id",
        (project_id, receipt.receipt_sha256),
    ).fetchall()
    if not rows:
        raise BaselineAuthRejected(
            "the validation receipt carries no authentication envelope"
        )

    keys = configured_validation_keys()
    for row in rows:
        envelope = LedgerValidationAuth.model_validate(json.loads(row["payload_json"]))
        if envelope.receipt_sha256 != receipt.receipt_sha256:
            continue
        key = keys.get(envelope.key_id)
        if key is None:
            continue
        if verify_auth_mac(envelope=envelope, key=key):
            return envelope

    raise BaselineAuthRejected(
        "the validation receipt carries no trusted authentication envelope"
    )
