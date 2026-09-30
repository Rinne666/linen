#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 /path/to/codeql-bundle-linux64.tar.zst [image-tag]" >&2
    echo "   or: $0 /path/to/codeql-bundle-linux-arm64.tar.zst [image-tag]" >&2
    exit 64
fi

bundle=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
image=${2:-linen-codeql:local}
case "$(basename "$bundle")" in
    codeql-bundle-linux64.tar.zst) platform=linux/amd64 ;;
    codeql-bundle-linux-arm64.tar.zst) platform=linux/arm64 ;;
    *)
        echo "Unsupported CodeQL bundle filename; expected an official Linux x64 or ARM64 bundle" >&2
        exit 65
        ;;
esac
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
# macOS ships bsdtar, whose external-compressor flags differ from GNU tar.
# Stream the official Zstandard archive through the portable stdin interface.
zstd -dc "$bundle" | tar -xf - -C "$build_root/extracted"
if [ -d "$build_root/extracted/codeql" ]; then
    mv "$build_root/extracted/codeql" "$build_root/codeql"
else
    echo "Bundle did not contain the expected codeql/ directory" >&2
    exit 65
fi
for query_pack in python-queries javascript-queries; do
    if [ ! -d "$build_root/codeql/qlpacks/codeql/$query_pack" ]; then
        echo "CodeQL bundle is missing required query pack: codeql/$query_pack" >&2
        exit 65
    fi
done

docker build --platform "$platform" --tag "$image" \
    --file "$repo_root/examples/codeql-image/Dockerfile" \
    "$build_root"
built_platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
if [ "$built_platform" != "$platform" ]; then
    echo "Built image platform $built_platform does not match bundle platform $platform" >&2
    exit 65
fi
docker run --rm --pull=never --platform "$platform" \
    --entrypoint /opt/codeql/codeql "$image" version
echo "Built $image for $platform. Configure audit.codeql.image to this local tag."
