# --- Release versioning -----------------------------------------------------------
# Imported by the root justfile. The workspace version (Cargo.toml
# [workspace.package].version) is the single source of truth: every crate inherits it,
# and the PDS reports it at _health/describeServer via env!("CARGO_PKG_VERSION").
# `set-version` bumps it; `release` derives the git tag from it, so the tag and the
# reported version can never drift. The release CI re-asserts the match.
#
# These recipes are thin entry points over real programs in scripts/release/ (arg
# validation, awk rewrites, fetch/ancestry/FORCE logic) — same "logic in scripts/,
# recipes as delegates" convention as the rest of the repo, so the shell gets
# shellcheck coverage.

# Bump the workspace version and resync Cargo.lock. Run in a reviewed PR, then
# `just release` from main after it merges. Usage: just set-version 0.3.1
set-version version:
    scripts/release/set-version.sh {{version}}

# Cut a release: create the annotated tag v{workspace version} and push it to origin.
# Tagging does NOT deploy — promote with `just deploy-production <tag>`. Run from a clean `main`.
release:
    scripts/release/release.sh

# Promote a release tag to production (advances the `production` branch Railway watches):
#   just deploy-production v0.3.1   # promote a specific tag
#   just deploy-production          # promote the highest vX.Y.Z tag
# Rolling back to an OLDER tag is a non-fast-forward; pass FORCE=1 to allow it.
deploy-production tag="":
    scripts/release/deploy-production.sh {{tag}}

# Verify the commit at HEAD is a valid production release point — used by the CI
# workflow on the `production` branch, and runnable locally.
verify-release-tag:
    scripts/release/verify-release-tag.sh
