"""The authentication envelopes of the CF-S2-B2-A proofs (D-054).

The two proofs of CF-S2-B2-A - the source identity attestation and the lineage
seal - share the *infrastructure* of the trusted issuance of CF-S2-B1 P1-C:
the same key ring, the same ``hmac.compare_digest`` verification and the same
fail-closed rule.  They do **not** share a table: an envelope about an
attestation is not an envelope about a seal, and neither of them is an
envelope about a validation receipt.

What makes an envelope trustworthy is unchanged (D-058): the MAC is made over
a domain separated input that binds the proof's digest and its project, so an
envelope cannot be replayed across proofs, across projects or across kinds.

    proof_auth_mac_input(
        domain            + b"\\x00" + canonical_json({project_id, proof_kind, proof_sha256})
    )

A deployment without a configured key can issue no envelope, and a proof
without an envelope stays readable without becoming trustworthy.
"""

from __future__ import annotations

import hmac
from hashlib import sha256

from linen.contracts.baseline import ProofAuthentication, proof_auth_mac_input

from .baseline_validation_auth import ValidationAuthKey, signing_key


def sign_proof_auth(
    *,
    proof_kind: str,
    proof_sha256: str,
    project_id: str,
    key: ValidationAuthKey,
) -> ProofAuthentication:
    """The authentication envelope of one proof, made with one key."""

    payload = proof_auth_mac_input(
        proof_kind=proof_kind, proof_sha256=proof_sha256, project_id=project_id
    )
    mac = hmac.new(key.secret, payload, sha256).hexdigest()
    return ProofAuthentication(
        auth_version=1,
        proof_kind=proof_kind,  # type: ignore[arg-type]
        key_id=key.key_id,
        proof_sha256=proof_sha256,
        project_id=project_id,
        mac=mac,
    )


def issue_proof_auth(
    *,
    proof_kind: str,
    proof_sha256: str,
    project_id: str,
    key_id: str | None = None,
) -> ProofAuthentication | None:
    """The authentication envelope of one proof, or nothing.

    A deployment that configured no key cannot issue an envelope, and therefore
    cannot produce a trustworthy proof.  That is the fail closed case, and it
    is reported as *no envelope* rather than as an envelope that turns out to
    be missing later.
    """

    key = signing_key(key_id)
    if key is None:
        return None
    return sign_proof_auth(
        proof_kind=proof_kind,
        proof_sha256=proof_sha256,
        project_id=project_id,
        key=key,
    )


def verify_proof_auth(*, envelope: ProofAuthentication, key: ValidationAuthKey) -> bool:
    """Whether the envelope's MAC was made with this key."""

    expected = hmac.new(key.secret, envelope.mac_input(), sha256).hexdigest()
    return hmac.compare_digest(expected, envelope.mac)
