"""Fixed standard-library runner for dispatcher-approved semantic searches.

This file is copied by trusted dispatcher code into an isolated analysis
container. Recipe data is JSON input; it is never interpreted as Python, a
shell command, a regular expression, or a filesystem path outside ``/repo``.
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path
import sys


MAX_FILES = 50_000
MAX_LITERAL_BYTES = 512
MAX_MATCHES = 300
MAX_LINE_BYTES = 8_000


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("expected one recipe input")
    plan = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if not isinstance(plan, dict) or set(plan) != {"operations"}:
        raise SystemExit("invalid recipe input")
    root = Path("/repo")
    files = sorted(
        path for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    if len(files) > MAX_FILES:
        raise SystemExit("frozen source file limit exceeded")
    output = []
    for index, operation in enumerate(plan["operations"]):
        if not isinstance(operation, dict) or set(operation) != {
            "capability", "literal", "path_globs", "max_results",
        } or operation["capability"] != "frozen_grep.literal":
            raise SystemExit("unsupported semantic recipe capability")
        literal = operation["literal"]
        path_globs = operation["path_globs"]
        max_results = operation["max_results"]
        if (
            not isinstance(literal, str) or not literal.strip()
            or len(literal.encode("utf-8")) > MAX_LITERAL_BYTES
            or "\x00" in literal or "\n" in literal or "\r" in literal
            or not isinstance(path_globs, list) or not path_globs
            or type(max_results) is not int or not 1 <= max_results <= MAX_MATCHES
        ):
            raise SystemExit("invalid semantic recipe operation")
        matches = []
        files_searched = 0
        skipped_long_lines = 0
        for path in files:
            relative = path.relative_to(root).as_posix()
            if not any(fnmatch.fnmatchcase(relative, pattern) for pattern in path_globs):
                continue
            files_searched += 1
            try:
                text = path.read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if literal not in line:
                    continue
                if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                    skipped_long_lines += 1
                    continue
                matches.append({"file": relative, "line": line_number, "code": line})
                if len(matches) >= max_results:
                    break
            if len(matches) >= max_results:
                break
        output.append({
            "operation": index,
            "files_searched": files_searched,
            "matches": matches,
            "skipped_long_lines": skipped_long_lines,
        })
    print(json.dumps({"operations": output}, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
