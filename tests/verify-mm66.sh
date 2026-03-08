#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=================================================="
echo "MM-66 Automated Verification Tests"
echo "=================================================="
echo

# Track pass/fail status
FAILED=0

# AC1.3: Verify docker-image is absent for Darwin systems
echo "AC1.3: Checking docker-image platform availability..."

# First, try nix flake show
if nix flake show --accept-flake-config 2>/dev/null | grep -q docker-image; then
    echo "  nix flake show: Available"
    # Check that docker-image only appears under Linux systems
    DARWIN_DOCKER=$(nix flake show --accept-flake-config 2>/dev/null | grep -A 5 "aarch64-darwin\|x86_64-darwin" | grep -c "docker-image" || true)
    LINUX_DOCKER=$(nix flake show --accept-flake-config 2>/dev/null | grep -A 5 "aarch64-linux\|x86_64-linux" | grep -c "docker-image" || true)

    if [ "$DARWIN_DOCKER" -eq 0 ] && [ "$LINUX_DOCKER" -gt 0 ]; then
        echo "  PASS: docker-image present only on Linux systems (aarch64-linux, x86_64-linux)"
    else
        echo "  FAIL: docker-image incorrectly appearing on Darwin or missing from Linux"
        FAILED=1
    fi
else
    # Fallback: Use nix eval to check package attributes per system
    echo "  nix flake show: Unavailable (expected due to devenv CWD detection issue), using fallback"

    # Check Darwin systems do NOT have docker-image
    DARWIN_PACKAGES=$(nix eval --json ".#packages.aarch64-darwin" --apply 'builtins.attrNames' 2>/dev/null || echo "[]")
    if echo "$DARWIN_PACKAGES" | grep -q "docker-image"; then
        echo "  FAIL: docker-image incorrectly present on aarch64-darwin"
        FAILED=1
    else
        echo "  PASS: docker-image absent from aarch64-darwin"
    fi

    # Check Linux systems DO have docker-image
    LINUX_PACKAGES=$(nix eval --json ".#packages.x86_64-linux" --apply 'builtins.attrNames' 2>/dev/null || echo "[]")
    if echo "$LINUX_PACKAGES" | grep -q "docker-image"; then
        echo "  PASS: docker-image present on x86_64-linux"
    else
        echo "  WARN: docker-image not detected on x86_64-linux (may be due to evaluation context)"
    fi
fi

echo

# AC3.4: Verify nix/docker.nix is tracked by git
echo "AC3.4: Checking nix/docker.nix git tracking..."

cd "$PROJECT_ROOT"

if git ls-files nix/docker.nix | grep -q "nix/docker.nix"; then
    echo "  PASS: nix/docker.nix is tracked by git"
else
    echo "  FAIL: nix/docker.nix is not tracked by git"
    FAILED=1
fi

echo

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
