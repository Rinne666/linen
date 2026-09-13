from __future__ import annotations

from linen.dispatcher.workers.adapters import ClaudeCodeDriver, CodexDriver, MockDriver, PiDriver
from linen.dispatcher.workers.base import WorkerDriver

# All drivers in this build are local-mode drivers: they invoke the host CLI
# (claude / codex / pi) in the project's working directory, using the user's
# own logged-in CLI configuration. No API keys are injected by linen.
DRIVERS: dict[str, WorkerDriver] = {
    "claudecode": ClaudeCodeDriver(),
    "codex": CodexDriver(local=True),
    "pi": PiDriver(local=True),
    "mock": MockDriver(),
}


def get_driver(name: str) -> WorkerDriver:
    try:
        return DRIVERS[name]
    except KeyError as exc:
        raise KeyError(f"unknown worker type: {name!r}") from exc
