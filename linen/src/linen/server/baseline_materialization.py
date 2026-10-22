"""Safe materialization of imported historical baseline artifacts (CF-S2-B1 P1-B).

A controlled import reads a historical run out of a declared root and records
what it read.  Materializing that run means writing its bytes into the project
workspace, and *that* is where a path is able to do damage: a name that was
assembled by string substitution can be made to point somewhere else, a
directory component can be a symbolic link, and a file that is created twice
has to fail rather than truncate what is there.

Two rules decide everything in this module.

**The directory identity is a content digest, not a name.**  The directory a
source materializes into is named after the full SHA-256 of a domain separated
digest of the *exact* source reference (D-053).  Two source references that
differ only in characters a path would treat as separators - ``a/b`` and
``a__b`` - therefore land in two different directories, and a directory name
never carries the meaning of the source it holds.

**Every filesystem step is taken relative to an already opened directory, and
no step follows a symbolic link.**  On a platform that can do that, each
component is created and opened relative to its parent's descriptor with
``O_NOFOLLOW`` and ``O_DIRECTORY``, and each file is created relative to the
directory descriptor with ``O_CREAT | O_EXCL | O_NOFOLLOW``.  Resolving a path
and then writing to it does not have that property: the resolved path can be
swapped for a symbolic link between the check and the write.

Where the platform cannot offer those guarantees, the materialization **fails
closed**.  It does not fall back to a weaker check and it does not write
anywhere else: an operator who needs the artifacts materialized on such a
platform has to run the server where the guarantees exist.  Windows is not a
supported linen platform (D-001), and it is exactly the platform that cannot
open a file without following a link, so it is the platform that fails closed.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Iterator

#: The domain separator of a materialization directory key.
#:
#: The separator keeps this digest from ever being the digest of anything
#: else the system computes, so a directory name can never be mistaken for
#: a ledger digest, a metadata digest or a reference digest.
MATERIALIZATION_KEY_DOMAIN = b"linen:baseline-materialization:v1\x00"

#: The directory the materialized artifacts live in, inside the project
#: workspace.
BASELINE_WORKSPACE_DIR = "baseline"


class BaselineMaterializationFailed(RuntimeError):
    """The artifacts could not be materialized safely."""


def _supports_no_follow_operations() -> bool:
    """Whether this platform can operate without following symbolic links."""

    return (
        os.name == "posix"
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.unlink in os.supports_dir_fd
    )


#: Whether this platform offers the no-follow, directory relative operations
#: the materialization is built on.
HAS_NO_FOLLOW_OPERATIONS = _supports_no_follow_operations()


def materialization_key(source_ref: str) -> str:
    """The directory identity of one historical source.

    The key is the full SHA-256 of the domain separator and the source
    reference, taken exactly as it was given: no trimming, no case folding,
    no path separator rewriting.  Two references that differ in any byte
    therefore produce two different keys, and the same reference always
    produces the same key - which is what makes a repeated materialization
    find the directory it wrote the first time (D-053).
    """

    if not isinstance(source_ref, str) or not source_ref:
        raise BaselineMaterializationFailed("the source reference is empty")
    return hashlib.sha256(
        MATERIALIZATION_KEY_DOMAIN + source_ref.encode("utf-8")
    ).hexdigest()


def _safe_segment(value: str, label: str) -> str:
    """A single path segment that cannot leave its parent directory."""

    if not isinstance(value, str) or not value:
        raise BaselineMaterializationFailed(f"the {label} is empty")
    if value in {".", ".."}:
        raise BaselineMaterializationFailed(f"the {label} is not a usable name")
    if "/" in value or "\\" in value or os.sep in value:
        raise BaselineMaterializationFailed(
            f"the {label} must be a single path segment"
        )
    if os.altsep and os.altsep in value:
        raise BaselineMaterializationFailed(
            f"the {label} must be a single path segment"
        )
    return value


def _trusted_root(workspace_root: Path) -> Path:
    """The resolved workspace root every materialized file has to stay in."""

    root = Path(workspace_root).expanduser()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BaselineMaterializationFailed(
            f"the workspace root could not be created: {exc}"
        ) from exc
    return Path(os.path.realpath(root))


def _open_root(root: Path) -> int:
    """Open the trusted root without following a symbolic link."""

    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise BaselineMaterializationFailed(
            f"the workspace root could not be opened without following a "
            f"symbolic link: {exc}"
        ) from exc


def _open_child_directory(parent: int, name: str) -> int:
    """Create and open one directory below an opened directory."""

    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    except OSError as exc:
        raise BaselineMaterializationFailed(
            f"the {name!r} directory could not be created: {exc}"
        ) from exc
    try:
        return os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
    except OSError as exc:
        raise BaselineMaterializationFailed(
            f"the {name!r} directory could not be opened without following a "
            f"symbolic link: {exc}"
        ) from exc


class MaterializationDirectory:
    """One historical source's materialization directory, opened no-follow.

    Every file operation is relative to the directory descriptor, so a
    component that is replaced by a symbolic link after the directory was
    opened cannot redirect a write: the write still lands in the directory
    that was actually opened, or it fails.
    """

    def __init__(self, *, path: Path, key: str, descriptor: int) -> None:
        self.path = path
        self.key = key
        self._descriptor = descriptor
        self._created: list[str] = []

    def __enter__(self) -> "MaterializationDirectory":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1

    @property
    def created_names(self) -> tuple[str, ...]:
        """The names this call created, in order."""

        return tuple(self._created)

    def existing_digest(self, name: str) -> str | None:
        """The digest of an already materialized file, or ``None``.

        A name that is occupied by a symbolic link, a directory or any other
        non-regular file is refused: there is no safe way to reuse it, and
        overwriting it would destroy whatever it points at.
        """

        try:
            info = os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BaselineMaterializationFailed(
                f"the {name!r} file could not be inspected: {exc}"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise BaselineMaterializationFailed(
                f"the {name!r} file is a symbolic link and will not be reused"
            )
        if not stat.S_ISREG(info.st_mode):
            raise BaselineMaterializationFailed(
                f"the {name!r} file is not a regular file and will not be reused"
            )
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=self._descriptor,
            )
        except OSError as exc:
            raise BaselineMaterializationFailed(
                f"the {name!r} file could not be opened without following a "
                f"symbolic link: {exc}"
            ) from exc
        try:
            # ``O_NOFOLLOW`` stops a symbolic link from being followed, but it
            # does not stop another process from replacing the file between
            # the check above and this open.  The descriptor is therefore
            # asked what it really is: a file that is not a regular file -
            # a fifo, a device, a socket - is refused here instead of being
            # read, and ``O_NONBLOCK`` keeps the open itself from waiting
            # for one.
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise BaselineMaterializationFailed(
                    f"the {name!r} file is not a regular file once it is opened"
                )
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                return hashlib.sha256(stream.read()).hexdigest()
        except OSError as exc:
            raise BaselineMaterializationFailed(
                f"the {name!r} file could not be read: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def write(self, name: str, payload: bytes, digest: str) -> bool:
        """Materialize one file, or reuse a byte identical one.

        Returns whether the file was created by this call.  A file that is
        already there with a different digest is refused instead of being
        replaced: the materialization is a record of what was imported, and
        a different content under the same name is a different record.
        """

        existing = self.existing_digest(name)
        if existing is not None:
            if existing != digest:
                raise BaselineMaterializationFailed(
                    f"the existing {name!r} file has a different digest and "
                    "will not be reused"
                )
            return False

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=self._descriptor)
        except OSError as exc:
            raise BaselineMaterializationFailed(
                f"the {name!r} file could not be created: {exc}"
            ) from exc
        self._created.append(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise BaselineMaterializationFailed(
                f"the {name!r} file could not be written: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return True

    def discard_created(self) -> None:
        """Remove the files this call created.

        A materialization that fails half way must not leave a file behind
        that a later reader could mistake for a materialized artifact, so
        the files this call created are removed when a later step fails.
        Files that were reused are left alone: they belong to an earlier,
        complete materialization.
        """

        while self._created:
            name = self._created.pop()
            try:
                os.unlink(name, dir_fd=self._descriptor)
            except OSError:
                pass


def open_materialization_directory(
    *, workspace_root: Path, project_id: str, source_ref: str
) -> MaterializationDirectory:
    """Open the directory one historical source materializes into.

    The directory is created when it does not exist and opened when it does;
    both happen relative to the parent directory's descriptor and without
    following a symbolic link, so a component that is a symbolic link is
    refused rather than used.
    """

    if not HAS_NO_FOLLOW_OPERATIONS:
        raise BaselineMaterializationFailed(
            "this platform cannot open baseline artifacts without following "
            "symbolic links, so the materialization fails closed"
        )

    key = materialization_key(source_ref)
    project_segment = _safe_segment(project_id, "project id")
    root = _trusted_root(workspace_root)

    descriptor = _open_root(root)
    path = root
    try:
        for segment in (project_segment, BASELINE_WORKSPACE_DIR, key):
            child = _open_child_directory(descriptor, segment)
            os.close(descriptor)
            descriptor = child
            path = path / segment
    except BaseException:
        os.close(descriptor)
        raise
    return MaterializationDirectory(path=path, key=key, descriptor=descriptor)
