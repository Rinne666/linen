#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 /path/to/codeql-bundle-linux-*.tar.zst [image-tag]" >&2
    exit 64
fi

bundle=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
image=${2:-linen-codeql:local}
repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
build_root=$(mktemp -d "${TMPDIR:-/tmp}/linen-codeql-image.XXXXXX")
trap 'rm -rf -- "$build_root"' EXIT INT TERM

if [ ! -f "$bundle" ]; then
    echo "CodeQL bundle not found: $bundle" >&2
    exit 66
fi
if ! command -v zstd >/dev/null 2>&1; then
    echo "zstd is required to extract the official CodeQL bundle" >&2
    exit 69
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker CLI is required to build the isolated CodeQL image" >&2
    exit 69
fi

mkdir -p "$build_root/extracted"
tar --use-compress-program=zstd -xf "$bundle" -C "$build_root/extracted"
if [ -d "$build_root/extracted/codeql" ]; then
    mv "$build_root/extracted/codeql" "$build_root/codeql"
else
    echo "Bundle did not contain the expected codeql/ directory" >&2
    exit 65
fi

docker build --tag "$image" \
    --file "$repo_root/examples/codeql-image/Dockerfile" \
    "$build_root"
echo "Built $image. Configure audit.codeql.image to this local tag."
