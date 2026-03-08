#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=================================================="
echo "MM-66 Automated Verification Tests"
echo "=================================================="
echo

FAILED=0

# AC1.3: Verify docker-image is absent for Darwin systems, present for Linux.
#
# Uses `nix eval` to inspect package attribute names per system — structurally
# reliable and avoids parsing `nix flake show` tree output with brittle grep -A
# heuristics. --accept-flake-config activates the Cachix binary cache; without
# it, evaluation on a cold machine may trigger a 20+ minute build.
echo "AC1.3: Checking docker-image platform availability..."

DARWIN_PACKAGES=$(nix eval --json --accept-flake-config ".#packages.aarch64-darwin" --apply 'builtins.attrNames')
if echo "$DARWIN_PACKAGES" | grep -q "docker-image"; then
    echo "  FAIL: docker-image incorrectly present on aarch64-darwin"
    FAILED=1
else
    echo "  PASS: docker-image absent from aarch64-darwin"
fi

LINUX_PACKAGES=$(nix eval --json --accept-flake-config ".#packages.x86_64-linux" --apply 'builtins.attrNames')
if echo "$LINUX_PACKAGES" | grep -q "docker-image"; then
    echo "  PASS: docker-image present on x86_64-linux"
else
    echo "  FAIL: docker-image missing from x86_64-linux"
    FAILED=1
fi

echo

# AC3.4: Verify nix/docker.nix is tracked by git.
echo "AC3.4: Checking nix/docker.nix git tracking..."

if git ls-files nix/docker.nix | grep -q "nix/docker.nix"; then
    echo "  PASS: nix/docker.nix is tracked by git"
else
    echo "  FAIL: nix/docker.nix is not tracked by git"
    FAILED=1
fi

echo

# Docker smoke test (Linux only — docker-image is not exposed on Darwin).
# Runs when Docker is available and relay:latest is already loaded, confirming
# the relay binary and libsqlite3.so are present in the image closure. The relay
# is a stub and may exit non-zero; that is acceptable. Only linker/missing-file
# errors indicate a broken image.
if command -v docker >/dev/null 2>&1 && docker image inspect relay:latest >/dev/null 2>&1; then
    echo "Docker smoke test: relay:latest found — verifying binary and dynamic linking..."
    OUTPUT=$(docker run --rm relay:latest 2>&1 || true)
    if echo "$OUTPUT" | grep -qE "no such file|error while loading shared libraries"; then
        echo "  FAIL: linker or missing-binary error detected"
        echo "  $OUTPUT"
        FAILED=1
    else
        echo "  PASS: relay:latest ran without linker or missing-binary errors"
    fi
    echo
fi

# Summary
echo "=================================================="
if [ $FAILED -eq 0 ]; then
    echo "Result: ALL CHECKS PASSED"
    echo "=================================================="
    exit 0
else
    echo "Result: SOME CHECKS FAILED"
    echo "=================================================="
    exit 1
fi
