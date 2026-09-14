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
