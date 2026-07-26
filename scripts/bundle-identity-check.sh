#!/usr/bin/env bash
# bundle-identity-check.sh — a bundle-id rename can never land as a one-line diff.
#
# The wallet's bundle identifier is not just a string: until MM-462 it silently doubled as
# two independent addressing schemes for the user's identity material.
#
#   1. The Keychain access group. With no `keychain-access-groups` entitlement, items land in
#      the implicit `$(AppIdentifierPrefix)<bundle-id>` group. A rename ⇒ every item — device
#      keys, Share 1, sessions, the managed-DID index — invisible.
#   2. The iCloud container `iCloud.<bundle-id>`, which holds the repo CAR snapshot and the
#      blob mirror — MM-451's disaster-recovery source. A rename ⇒ both gone.
#
# Both fail *silently*: the app comes up looking like a clean install. A user who had not kept
# Share 3 would be unrecoverable through no action of their own.
#
# This gate pins each app's identifier and asserts the net is in place, so the rename has to be
# a deliberate edit to this file — which is where the checklist lives. See ADR-0030 and
# docs/design-plans/2026-07-24-wallet-identity-durability.md §4.
#
# Linux-runnable (greps only); part of `just ci` / `just ci-pds`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --- The pins -----------------------------------------------------------------------------
#
# Changing either value is the rename. A rename is NOT an update: App Store Connect treats the
# bundle id as immutable for an existing app record, so org.obsign.* means a new record, a new
# App ID, and on-device a separate install. Users must be told to install the new app BEFORE
# deleting the old one — that is what keeps the legacy Keychain group readable. Nothing may
# depend on Keychain items outliving deletion of the old install.
#
# Before you change a pin, ALL of the following must already have shipped and baked in a
# released build that users have had a full release cycle to install:
#
#   [ ] The stable Keychain access group below is declared FIRST in the app's
#       Entitlements.ios.plist, and has been in a shipped release — so items already live
#       there rather than in the implicit legacy group.
#   [ ] The legacy access group below is still declared. It stops being implicit the moment
#       the bundle id moves; only the explicit entry keeps pre-rename items readable.
#   [ ] FROZEN_ICLOUD_CONTAINER stays exactly as-is. An iCloud container id cannot be renamed;
#       Apple permits one that does not match the bundle id (ADR-0030).
#       (The access groups themselves need NO portal registration — a provisioning profile
#       authorizes the whole team prefix via a `<TeamID>.*` wildcard. Only iCloud does.)
#   [ ] BOTH App IDs (old and new) have the iCloud capability enabled with the SAME container
#       id below. This is the step that carries the backups across, and it is easy to skip
#       because the container will not match the new bundle id — that mismatch is correct.
#   [ ] The release notes / onboarding tell users to install the new app before deleting the
#       old one. The app cannot enforce this.
#
# A rename shipped in the same release as the access-group change strands anyone who skips
# that version. The bake time is the point.
WALLET_BUNDLE_ID='dev.malpercio.identitywallet'
ADMIN_BUNDLE_ID='dev.malpercio.admincompanion'
STABLE_ACCESS_GROUP='org.obsign.shared'
LEGACY_ACCESS_GROUP='dev.malpercio.identitywallet'
FROZEN_ICLOUD_CONTAINER='iCloud.dev.malpercio.identitywallet'

WALLET_DIR="${REPO_ROOT}/apps/identity-wallet/src-tauri"
ADMIN_DIR="${REPO_ROOT}/apps/admin-companion/src-tauri"
WALLET_ENT="${WALLET_DIR}/Entitlements.ios.plist"
WALLET_INFO="${WALLET_DIR}/Info.ios.plist"
KEYCHAIN_RS="${WALLET_DIR}/src/keychain.rs"

fail=0
note() {
  echo "bundle-identity-check: FAIL — $1" >&2
  fail=1
}

# --- 1. Identifiers match their pins -------------------------------------------------------
check_identifier() {
  local app="$1" expected="$2" conf="${REPO_ROOT}/apps/$1/src-tauri/tauri.conf.json"
  local actual
  actual="$(sed -n 's/^[[:space:]]*"identifier"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${conf}")"
  if [ -z "${actual}" ]; then
    note "could not read the bundle identifier from ${conf}"
    return
  fi
  if [ "${actual}" != "${expected}" ]; then
    note "${app} bundle id is '${actual}' but this gate pins '${expected}'.
  A rename changes the Keychain access group AND the iCloud container at once, and both fail
  silently — the app comes up looking like a clean install. Work the checklist at the top of
  $(basename "$0"), confirm the access-group change has shipped and baked for a full release
  cycle, then update the pin in the same PR as the rename."
  fi
}
check_identifier identity-wallet "${WALLET_BUNDLE_ID}"
check_identifier admin-companion "${ADMIN_BUNDLE_ID}"

# --- 2. The access-group net ---------------------------------------------------------------
# Extract the keychain-access-groups <string> values in declaration order. Order is the
# mechanism: iOS writes a new item into the FIRST entitled group and searches EVERY entitled
# group on a read that names none.
groups="$(
  sed -n '/<key>keychain-access-groups<\/key>/,/<\/array>/p' "${WALLET_ENT}" |
    sed -n 's/.*<string>\(.*\)<\/string>.*/\1/p'
)"
if [ -z "${groups}" ]; then
  note "wallet Entitlements.ios.plist declares no keychain-access-groups — every item would
  land in the implicit \$(AppIdentifierPrefix)<bundle-id> group, which a rename destroys."
else
  first="$(printf '%s\n' "${groups}" | head -n1)"
  if [ "${first}" != "\$(AppIdentifierPrefix)${STABLE_ACCESS_GROUP}" ]; then
    note "the stable group must be FIRST in keychain-access-groups (that position is what makes
  it the write target); found '${first}', expected '\$(AppIdentifierPrefix)${STABLE_ACCESS_GROUP}'."
  fi
  if ! printf '%s\n' "${groups}" | grep -qxF -- "\$(AppIdentifierPrefix)${LEGACY_ACCESS_GROUP}"; then
    note "the legacy group '\$(AppIdentifierPrefix)${LEGACY_ACCESS_GROUP}' is no longer declared.
  It is implicit only while the bundle id still matches it; dropping the explicit entry orphans
  every item written before the stable group existed."
  fi
fi

# The Rust constants name the same groups the entitlement declares — keychain.rs's module docs
# and its compile-time test both key off them.
for const_pair in "STABLE_ACCESS_GROUP ${STABLE_ACCESS_GROUP}" "LEGACY_ACCESS_GROUP ${LEGACY_ACCESS_GROUP}"; do
  name="${const_pair%% *}"
  value="${const_pair#* }"
  if ! grep -qF -- "pub const ${name}: &str = \"${value}\";" "${KEYCHAIN_RS}"; then
    note "keychain.rs's ${name} does not equal '${value}' — the entitlement and the code that
  documents it have diverged."
  fi
done

# --- 3. The iCloud container is frozen, not derived from the bundle id ----------------------
# Checked against the literal, NOT against the current bundle id: deriving it would let a
# rename silently redefine "correct" and orphan the backups this exists to protect.
if ! grep -qF -- "${FROZEN_ICLOUD_CONTAINER}" "${WALLET_ENT}"; then
  note "wallet Entitlements.ios.plist no longer names the frozen iCloud container
  '${FROZEN_ICLOUD_CONTAINER}'. A container id cannot be renamed; changing it orphans the repo
  CAR snapshot and the blob mirror (ADR-0030)."
fi
if ! grep -qF -- "${FROZEN_ICLOUD_CONTAINER}" "${WALLET_INFO}"; then
  note "wallet Info.ios.plist's NSUbiquitousContainers no longer names
  '${FROZEN_ICLOUD_CONTAINER}' — the mirror would vanish from the Files app."
fi

# --- 4. Least privilege on the console -----------------------------------------------------
# The operator console's keychain items are all re-derivable by re-pairing, so it gets no
# shared group. (ios-template-check already forbids it an iCloud container.)
if grep -qF 'keychain-access-groups' "${ADMIN_DIR}/Entitlements.ios.plist"; then
  note "admin-companion declares keychain-access-groups. Its keychain items are re-derivable by
  re-pairing, so it has no need to share a group — and sharing one would widen what the wallet's
  identity material is reachable from."
fi

if [ "${fail}" -ne 0 ]; then
  exit 1
fi
echo "bundle-identity-check: OK — bundle ids pinned, access-group net declared, iCloud container frozen"
