"""Common validation and canonical serialization helpers.

Canonicalization is intentionally independent of Pydantic's JSON formatting:
it recursively sorts mapping keys and unordered set members before hashing.
Lists and tuples preserve their order; contracts opt individual fields into
unordered normalization when their semantics are set-like.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
import hashlib
import json
import re
import unicodedata
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, field_validator


SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
CONTENT_DIGEST_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")


class FrozenList(list[Any]):
    """A list-compatible container that cannot be changed in place.

    Contract fields intentionally keep list semantics for callers and for
    Pydantic's JSON serializers, while preventing the aliasing that would
    otherwise let a caller silently invalidate a derived digest.
    """

    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("contract collections are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __iadd__ = _immutable
    __imul__ = _immutable
    append = _immutable
    clear = _immutable
    extend = _immutable
    insert = _immutable
    pop = _immutable
    remove = _immutable
    reverse = _immutable
    sort = _immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenList":
        existing = memo.get(id(self))
        if existing is not None:
            return existing
        copied = FrozenList()
        memo[id(self)] = copied
        list.extend(copied, (deepcopy(item, memo) for item in self))
        return copied


class FrozenDict(dict[Any, Any]):
    """A dict-compatible container that cannot be changed in place."""

    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("contract collections are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenDict":
        existing = memo.get(id(self))
        if existing is not None:
            return existing
        copied = FrozenDict()
        memo[id(self)] = copied
        for key, value in self.items():
            dict.__setitem__(copied, deepcopy(key, memo), deepcopy(value, memo))
        return copied


class FrozenSet(set[Any]):
    """A set-compatible container that cannot be changed in place."""

    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("contract collections are immutable")

    add = _immutable
    clear = _immutable
    difference_update = _immutable
    discard = _immutable
    intersection_update = _immutable
    pop = _immutable
    remove = _immutable
    symmetric_difference_update = _immutable
    update = _immutable
    __ior__ = _immutable
    __iand__ = _immutable
    __isub__ = _immutable
    __ixor__ = _immutable

    def __deepcopy__(self, memo: dict[int, Any]) -> "FrozenSet":
        existing = memo.get(id(self))
        if existing is not None:
            return existing
        copied = FrozenSet()
        memo[id(self)] = copied
        for item in self:
            set.add(copied, deepcopy(item, memo))
        return copied


def _freeze_value(value: Any) -> Any:
    """Copy nested JSON-like values into immutable, serialization-safe forms."""

    if isinstance(value, BaseModel):
        # Nested contract models are already assignment-immutable, but their
        # arbitrary payload fields still need the same recursive treatment.
        for name, item in vars(value).items():
            object.__setattr__(value, name, _freeze_value(item))
        return value
    if isinstance(value, FrozenList | list):
        return FrozenList(_freeze_value(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, FrozenDict | Mapping):
        return FrozenDict((_freeze_value(key), _freeze_value(item)) for key, item in value.items())
    if isinstance(value, FrozenSet | set | frozenset):
        return FrozenSet(_freeze_value(item) for item in value)
    return value


def _freeze_model_values(model: BaseModel) -> None:
    for name, value in vars(model).items():
        object.__setattr__(model, name, _freeze_value(value))


def _canonical_value(value: Any) -> Any:
    """Return JSON-compatible data with deterministic mapping/set ordering.

    Lists and tuples intentionally retain their order: evidence paths,
    call-chains, and other sequences can be semantically ordered.  Contracts
    whose fields are sets must opt into field-level normalization below.
    """

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=False)
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (set, frozenset)):
        members = [_canonical_value(item) for item in value]
        return sorted(members, key=_sort_key)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def _sort_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_data(
    value: Any,
    *,
    exclude: set[str] | None = None,
    unordered_fields: set[str] | frozenset[str] | None = None,
) -> Any:
    """Normalize a model or JSON-like value for reproducible hashing."""

    if isinstance(value, BaseModel) and exclude:
        value = value.model_dump(mode="json", exclude=exclude, exclude_none=False)
    elif isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=False)
    if unordered_fields and isinstance(value, Mapping):
        value = dict(value)
        for field in unordered_fields:
            collection = value.get(field)
            if isinstance(collection, (list, tuple, set, frozenset)):
                normalized = [_canonical_value(item) for item in collection]
                value[field] = sorted(normalized, key=_sort_key)
    return _canonical_value(value)


def canonical_json(
    value: Any,
    *,
    exclude: set[str] | None = None,
    unordered_fields: set[str] | frozenset[str] | None = None,
) -> str:
    """Serialize a value as compact, UTF-8-safe canonical JSON."""

    return json.dumps(
        canonical_data(value, exclude=exclude, unordered_fields=unordered_fields),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_digest(
    value: Any,
    *,
    exclude: set[str] | None = None,
    unordered_fields: set[str] | frozenset[str] | None = None,
) -> str:
    """Return a bare SHA-256 hex digest of canonical JSON data."""

    return hashlib.sha256(
        canonical_json(value, exclude=exclude, unordered_fields=unordered_fields).encode("utf-8")
    ).hexdigest()


def content_digest(value: Any, *, exclude: set[str] | None = None) -> str:
    """Return a namespaced digest suitable for manifest references."""

    return f"sha256:{canonical_digest(value, exclude=exclude)}"


def validate_sha256(value: str) -> str:
    value = value.strip().lower()
    if not SHA256_RE.fullmatch(value):
        raise ValueError("sha256 must be exactly 64 hexadecimal characters")
    return value


def validate_content_digest(value: str) -> str:
    value = value.strip().lower()
    if not CONTENT_DIGEST_RE.fullmatch(value):
        raise ValueError("digest must have the form sha256:<64 hexadecimal characters>")
    return value


def validate_workspace_relative_path(value: str) -> str:
    """Reject absolute paths and parent traversal in new artifact references."""

    from pathlib import PurePosixPath

    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        raise ValueError("workspace_path must not contain control characters")
    path = value.strip()
    if not path:
        raise ValueError("workspace_path must not be empty")
    normalized = path.replace("\\", "/")
    if normalized.startswith("/") or WINDOWS_ABSOLUTE_RE.match(path):
        raise ValueError("workspace_path must be relative to the workspace")
    parts = PurePosixPath(normalized).parts
    if ".." in parts:
        raise ValueError("workspace_path must not contain '..'")
    return normalized


# --- upstream-compatible coverage primitives (CF-S1-A / CF-S1-B) --------------
# These mirror cloudflare/security-audit-skill validate-coverage-ledger.cjs at
# commit c1c8a8c (vendored under linen/third_party/cloudflare_security_audit_skill).
# They live here because two layers must agree with the pinned Node validator:
# the dispatcher contract layer, which admits model output, and the coverage
# identity layer, which derives ids from operator-declared references.  The
# JavaScript-specific details are intentional: "equivalent" means the same
# accept/reject decision as the pinned validator, including its Unicode rules.

CF_MAX_LIST_ITEMS = 1000
CF_MAX_TEXT_LENGTH = 4096
CF_MAX_CANONICAL_REF_LENGTH = 1024

#: The four descriptive dimensions a canonical coverage id is derived from.
CF_CANONICAL_REF_FIELDS: tuple[str, ...] = (
    "surface", "boundary", "subsystem", "attack_class",
)

#: Retired activity identifier scheme.  Legacy ids stay readable only through
#: an explicit alias map (D-017); they are never accepted as an active id.
CF_LEGACY_COVERAGE_ID_RE = re.compile(r"cov-[0-9a-z-]+")

# ECMAScript WhiteSpace + LineTerminator: the exact set JavaScript's
# String.prototype.trim removes.  Python's str.strip() also removes
# U+001C..U+001F and U+0085, so it is *not* equivalent.
_CF_JS_WHITESPACE = frozenset(
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)

# Default_Ignorable_Code_Point members that are neither Cc nor Cf and would
# therefore slip past a category-only check.
_CF_DEFAULT_IGNORABLE_EXTRA = frozenset(
    "\u034f\u115f\u1160\u17b4\u17b5\u180b\u180c\u180d\u180f\u2065\u3164\uffa0"
    "\ufe00\ufe01\ufe02\ufe03\ufe04\ufe05\ufe06\ufe07\ufe08\ufe09\ufe0a\ufe0b"
    "\ufe0c\ufe0d\ufe0e\ufe0f"
) | frozenset(chr(code_point) for code_point in range(0xE0100, 0xE01F0))

_CF_AGENT_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_CF_WINDOWS_RESERVED_AGENT_ID_RE = re.compile(
    r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])"
)
_CF_WINDOWS_RESERVED_COMPONENT_RE = re.compile(
    r"(?:con|prn|aux|nul|clock\$|conin\$|conout\$"
    r"|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|\Z)",
    re.IGNORECASE,
)

# Bytes the upstream percent encoding keeps verbatim.
_CF_UNRESERVED_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def cf_js_trim(value: str) -> str:
    """Trim exactly the characters JavaScript's String.prototype.trim removes."""

    start = 0
    end = len(value)
    while start < end and value[start] in _CF_JS_WHITESPACE:
        start += 1
    while end > start and value[end - 1] in _CF_JS_WHITESPACE:
        end -= 1
    return value[start:end]


def cf_utf16_length(value: str) -> int | None:
    """JavaScript's String.length, or None when the string is not valid UTF-16."""

    try:
        return len(value.encode("utf-16-le")) // 2
    except UnicodeEncodeError:
        return None


def cf_has_forbidden_path_character(value: str) -> bool:
    """Whether the value contains a character upstream forbids in paths."""

    for character in value:
        if character in _CF_DEFAULT_IGNORABLE_EXTRA:
            return True
        if unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"}:
            return True
    return False


def cf_has_visible_character(value: str) -> bool:
    """Whether the value contains at least one character upstream considers visible."""

    for character in value:
        if character in _CF_JS_WHITESPACE:
            continue
        if character in _CF_DEFAULT_IGNORABLE_EXTRA:
            continue
        if unicodedata.category(character) in {"Cc", "Cf"}:
            continue
        return True
    return False


def cf_is_visible_text(value: object, max_length: int = CF_MAX_TEXT_LENGTH) -> bool:
    """Upstream isVisibleText: visible, trimmed, bounded, valid UTF-16."""

    if not isinstance(value, str) or not value:
        return False
    length = cf_utf16_length(value)
    if length is None or length > max_length:
        return False
    if cf_js_trim(value) != value:
        return False
    return cf_has_visible_character(value)


def cf_is_safe_relative_path(value: object) -> bool:
    """Upstream isSafeRelativePath: a repository-relative path, no traversal."""

    if not isinstance(value, str) or not value:
        return False
    if cf_utf16_length(value) is None:
        return False
    if cf_js_trim(value) != value:
        return False
    if cf_has_forbidden_path_character(value):
        return False
    if "\\" in value or ":" in value:
        return False
    if value.startswith("/"):
        return False
    if re.match(r"[A-Za-z]:", value):
        return False
    if value.startswith("~"):
        return False
    for segment in value.split("/"):
        if not segment or segment in {".", ".."}:
            return False
        if segment.endswith(" ") or segment.endswith("."):
            return False
        if _CF_WINDOWS_RESERVED_COMPONENT_RE.match(segment):
            return False
    return True


def cf_is_safe_agent_id(value: object) -> bool:
    """Upstream isSafeAgentId: lowercase canonical id, no Windows reserved name."""

    if not isinstance(value, str):
        return False
    if _CF_AGENT_ID_RE.fullmatch(value) is None:
        return False
    return _CF_WINDOWS_RESERVED_AGENT_ID_RE.fullmatch(value) is None


def cf_is_owned_artifact_path(value: object, agent_id: object) -> bool:
    """Upstream isOwnedArtifactPath: artifact must live under its own agent."""

    if not cf_is_safe_agent_id(agent_id) or not cf_is_safe_relative_path(value):
        return False
    prefix = f"agents/{agent_id}/artifacts/"
    return value.startswith(prefix) and len(value) > len(prefix)


def cf_encode_canonical_ref(value: object) -> str:
    """Percent-encode one canonical reference exactly like the upstream encoder.

    The reference must be visible text, free of forbidden path characters and
    already in Unicode NFC form; the UTF-8 bytes are then percent-encoded with
    upper-case hexadecimal digits.
    """

    if not cf_is_visible_text(value, CF_MAX_CANONICAL_REF_LENGTH):
        raise ValueError("invalid canonical reference")
    assert isinstance(value, str)
    if cf_has_forbidden_path_character(value):
        raise ValueError("invalid canonical reference")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("invalid canonical reference")
    encoded: list[str] = []
    for byte in value.encode("utf-8"):
        if byte in _CF_UNRESERVED_BYTES:
            encoded.append(chr(byte))
        else:
            encoded.append(f"%{byte:02X}")
    return "".join(encoded)


def cf_canonical_coverage_id(canonical_refs: Mapping[str, Any]) -> str:
    """Derive the canonical coverage id from its descriptive references.

    The four dimensions are joined with "::" after each one has been
    percent-encoded.  An optional fifth "lifecycle" dimension is accepted so
    the result matches the upstream validator, but linen's active protocol
    stays four-dimensional (N1).
    """

    if not isinstance(canonical_refs, Mapping):
        raise ValueError("canonical_refs must be an object")
    fields = list(CF_CANONICAL_REF_FIELDS)
    if "lifecycle" in canonical_refs:
        fields.append("lifecycle")
    if set(canonical_refs) != set(fields):
        raise ValueError("canonical_refs has missing or unexpected fields")
    return "::".join(cf_encode_canonical_ref(canonical_refs[field]) for field in fields)


def cf_is_legacy_coverage_id(value: object) -> bool:
    """Whether a coverage id uses the retired ``cov-<n>`` scheme."""

    return isinstance(value, str) and CF_LEGACY_COVERAGE_ID_RE.fullmatch(value) is not None


def cf_resolve_legacy_coverage_id(
    coverage_id: str,
    aliases: Mapping[tuple[str, str], str],
    *,
    legacy_source_id: str,
) -> str:
    """Resolve a retired ``cov-<n>`` id through an explicit alias map (D-017).

    ``aliases`` maps ``(legacy_source_id, legacy_coverage_id)`` to the canonical
    coverage id.  Nothing is inferred from the id itself: a legacy id that has
    no recorded mapping raises an ``unresolved_alias`` error rather than being
    guessed from a similar name.
    """

    if not cf_is_legacy_coverage_id(coverage_id):
        raise ValueError(f"not a legacy coverage id: {coverage_id!r}")
    try:
        return aliases[(legacy_source_id, coverage_id)]
    except KeyError:
        raise ValueError(
            f"unresolved_alias: no canonical coverage id for {coverage_id!r} "
            f"in legacy source {legacy_source_id!r}"
        ) from None


#: Upstream validate-coverage-ledger.cjs PRIOR_STATUSES (11 values, @ c1c8a8c).
#: A prior status is only meaningful when it was derived from a verifiable
#: historical baseline: "none" records a *verified absence* of a compatible
#: ledger, never "not known yet" (CF-S1-C, E48).
CF_PRIOR_STATUSES: tuple[str, ...] = (
    "new",
    "prior_confirmed_same_source",
    "prior_confirmed_changed_source",
    "prior_needs_validation",
    "prior_deferred",
    "prior_blocked",
    "prior_out_of_scope",
    "prior_covered_same_source",
    "prior_covered_changed_source",
    "prior_rejected_claim_changed",
    "none",
)

#: The event types the coverage event ledger may store.  CF-S1-C only opens
#: ``unit_registered``; ``wave_started`` and ``attempt_recorded`` belong to
#: CF-S2-A.
CF_COVERAGE_EVENT_TYPES: tuple[str, ...] = (
    "unit_registered",
    "wave_started",
    "attempt_recorded",
)

#: Baseline kinds recorded alongside a registration event.
CF_BASELINE_KINDS: tuple[str, ...] = ("no_compatible_ledger", "compatible_ledger")


def cf_canonical_json(payload: Mapping[str, Any]) -> str:
    """Serialize a payload so equal content always yields equal text.

    A fixed key order and fixed separators make the digest independent of
    insertion order, so a legitimate retry compares equal to the original
    write.  Text is emitted as UTF-8 without ASCII escaping so the digest
    covers the same bytes the ledger stores.
    """

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def cf_payload_digest(payload: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical JSON form of a payload."""

    return hashlib.sha256(cf_canonical_json(payload).encode("utf-8")).hexdigest()


class ContractModel(BaseModel):
    """Base class for public contracts: closed and assignment-immutable."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_assignment=True,
    )
    CURRENT_SCHEMA_VERSION: ClassVar[int] = 1

    CANONICAL_UNORDERED_FIELDS: ClassVar[frozenset[str]] = frozenset()
    CANONICAL_EXCLUDE_FIELDS: ClassVar[frozenset[str]] = frozenset()

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        _freeze_model_values(self)

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> "ContractModel":
        # Pydantic's model_copy intentionally skips validation.  Preserve
        # that API behavior, but still detach and freeze updated containers so
        # the copy cannot be mutated through a caller-owned list or dict.
        copied = super().model_copy(update=update, deep=deep)
        _freeze_model_values(copied)
        return copied

    def _canonical_exclude(self, exclude: set[str] | None) -> set[str]:
        return set(self.CANONICAL_EXCLUDE_FIELDS) | set(exclude or ())

    def canonical_json(self, *, exclude: set[str] | None = None) -> str:
        return canonical_json(
            self,
            exclude=self._canonical_exclude(exclude),
            unordered_fields=self.CANONICAL_UNORDERED_FIELDS,
        )

    def canonical_digest(self, *, exclude: set[str] | None = None) -> str:
        return canonical_digest(
            self,
            exclude=self._canonical_exclude(exclude),
            unordered_fields=self.CANONICAL_UNORDERED_FIELDS,
        )

    @field_validator("schema_version", check_fields=False)
    @classmethod
    def _schema_version_is_current(cls, value: int) -> int:
        if value != cls.CURRENT_SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version: {value}")
        return value
