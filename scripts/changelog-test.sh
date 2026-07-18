#!/usr/bin/env bash
# Hermetic behavior tests for the changelog presence gate and release roll-up.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git init -q "$tmp/repo"
cd "$tmp/repo"
git config user.email changelog-test@example.invalid
git config user.name changelog-test
mkdir -p scripts/release changelog.d crates/pds/src bin
cp "$repo_root/scripts/changelog-check.sh" scripts/
cp "$repo_root/scripts/release/set-version.sh" scripts/release/

cat > Cargo.toml <<'EOF'
[workspace]

[workspace.package]
version = "1.0.0"
EOF
touch Cargo.lock
cat > CHANGELOG.md <<'EOF'
# Changelog

## [1.0.0] - 2026-01-01

- Initial fixture release.
EOF
cat > changelog.d/README.md <<'EOF'
# Changelog fragments
EOF
cat > crates/pds/src/lib.rs <<'EOF'
pub fn shipped() {}
EOF
git add .
git commit -qm base
base="$(git rev-parse HEAD)"

cat > crates/pds/src/lib.rs <<'EOF'
pub fn shipped_change() {}
EOF
git add crates/pds/src/lib.rs
git commit -qm shipped-change
if scripts/changelog-check.sh "$base" >"$tmp/missing.out" 2>&1; then
  echo "✗ changelog gate accepted a shipped change without a fragment" >&2
  exit 1
fi
grep -q 'adds no changelog.d' "$tmp/missing.out"

cat > changelog.d/mm-358.added.md <<'EOF'
Added the first fixture capability.
EOF
cat > changelog.d/mm-358.fixed.md <<'EOF'
Fixed the fixture behavior.
EOF
git add changelog.d
git commit -qm fragments
scripts/changelog-check.sh "$base" >/dev/null

# set-version only needs cargo metadata to succeed in this fixture. The production script
# still invokes the real Cargo command, preserving its existing lockfile-resync behavior.
cat > bin/cargo <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x bin/cargo
PATH="$PWD/bin:$PATH" CHANGELOG_DATE=2026-07-14 scripts/release/set-version.sh 1.1.0 >/dev/null

grep -q '^version = "1.1.0"$' Cargo.toml
grep -q '^## \[1.1.0\] - 2026-07-14$' CHANGELOG.md
grep -q '^### Added$' CHANGELOG.md
grep -q '^- Added the first fixture capability\.$' CHANGELOG.md
grep -q '^### Fixed$' CHANGELOG.md
grep -q '^- Fixed the fixture behavior\.$' CHANGELOG.md
test "$(grep -n '^## \[' CHANGELOG.md | head -1 | cut -d: -f2-)" = '## [1.1.0] - 2026-07-14'
test ! -e changelog.d/mm-358.added.md
test ! -e changelog.d/mm-358.fixed.md
test -e changelog.d/README.md

# The release roll-up commit changes shipped surfaces (Cargo.toml/Cargo.lock) yet carries no
# fragment, because set-version just consumed them all. The gate must recognize this shape and
# pass — otherwise every release PR fails the very gate the release just satisfied.
git add -A
git commit -qm 'release: set version 1.1.0'
scripts/changelog-check.sh "$base" >"$tmp/rollup.out" 2>&1
grep -q 'release roll-up detected' "$tmp/rollup.out"

# A fragment already sitting in changelog.d/ (left over from an unmerged sibling or an
# unconsumed earlier PR) must NOT satisfy the presence gate for a change that adds no
# fragment of its own — presence is judged on fragments added since the base.
cat > changelog.d/mm-999.added.md <<'EOF'
Added by an earlier, unrelated change; already present at the PR base.
EOF
git add changelog.d
git commit -qm pre-existing-fragment
base_stale="$(git rev-parse HEAD)"
cat > crates/pds/src/lib.rs <<'EOF'
pub fn shipped_change_without_own_fragment() {}
EOF
git add crates/pds/src/lib.rs
git commit -qm shipped-change-no-own-fragment
if scripts/changelog-check.sh "$base_stale" >"$tmp/stale.out" 2>&1; then
  echo "✗ changelog gate accepted a shipped change whose only fragment pre-dates the base" >&2
  exit 1
fi
grep -q 'adds no changelog.d' "$tmp/stale.out"

# Adding the change's own fragment (alongside the pre-existing one) satisfies the gate.
cat > changelog.d/mm-1000.fixed.md <<'EOF'
Fixed the thing this change actually ships.
EOF
git add changelog.d
git commit -qm own-fragment
scripts/changelog-check.sh "$base_stale" >/dev/null

echo "✓ changelog gate, release roll-up, and added-fragment presence behavior"
