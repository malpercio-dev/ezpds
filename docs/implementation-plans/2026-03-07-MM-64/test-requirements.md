# MM-64 Test Requirements

**Ticket:** MM-64 — Nix Flake + devenv Development Shell
**Phases:** 2 (Phase 1: configuration files, Phase 2: operational verification)
**Test approach:** All verification is operational (command execution and output inspection). There are no unit tests — this is infrastructure-only.

---

## Automated Operational Tests

These tests run inside a non-interactive Nix devShell via `nix develop --command`. Each test maps to a specific acceptance criterion and can be executed by a script or CI job on the target platform.

### Test 1: Dev shell activates on macOS

**Criterion:** MM-64.AC1.1
**Test type:** Operational — shell activation
**What to run:**

```bash
nix develop --command bash -c 'echo "shell activated"'
```

**Expected output:** The command exits with code 0 and prints `shell activated`. Any non-zero exit code or Nix evaluation error is a failure.

**Rationale:** Phase 2, Task 1 generates `flake.lock` by running `nix develop`. Phase 2, Task 2 runs all tool checks inside the shell via `nix develop --command`. This test isolates the activation check from the tool checks. Only covers `aarch64-darwin` or `x86_64-darwin` depending on the machine running the test — Linux coverage requires separate verification (see Human Verification section).

---

### Test 2: rustc is stable

**Criterion:** MM-64.AC2.1, MM-64.AC3.1
**Test type:** Operational — version string assertion
**What to run:**

```bash
nix develop --command bash -c '
  VERSION=$(rustc --version)
  echo "$VERSION"
  echo "$VERSION" | grep -qv "nightly" || { echo "FAIL: nightly detected"; exit 1; }
  echo "$VERSION" | grep -qv "beta" || { echo "FAIL: beta detected"; exit 1; }
  echo "OK: rustc is stable"
'
```

**Expected output:** A version string like `rustc 1.XX.0 (hash YYYY-MM-DD)` with no `nightly` or `beta` substring, followed by `OK: rustc is stable`. Exit code 0.

**Rationale:** `rust-toolchain.toml` sets `channel = "stable"`. `devenv.nix` reads this file via `languages.rust.toolchainFile`. This test confirms the toolchain channel propagated correctly through devenv/rust-overlay. Satisfies both AC2.1 (stable release) and AC3.1 (version matches rust-toolchain.toml's stable channel).

---

### Test 3: cargo is available

**Criterion:** MM-64.AC2.2
**Test type:** Operational — command presence
**What to run:**

```bash
nix develop --command bash -c 'cargo --version'
```

**Expected output:** `cargo 1.XX.0 (hash YYYY-MM-DD)`. Exit code 0.

**Rationale:** `cargo` is part of the Rust toolchain activated by `languages.rust.enable = true` in `devenv.nix`.

---

### Test 4: rust-analyzer is available

**Criterion:** MM-64.AC2.3
**Test type:** Operational — command presence
**What to run:**

```bash
nix develop --command bash -c 'rust-analyzer --version'
```

**Expected output:** A version string (e.g., `rust-analyzer 1.XX.0-stable (hash YYYY-MM-DD)`). Exit code 0.

**Rationale:** `rust-toolchain.toml` lists `rust-analyzer` in `components`. devenv reads this file and includes the component via rust-overlay.

---

### Test 5: clippy is available

**Criterion:** MM-64.AC2.4
**Test type:** Operational — command presence
**What to run:**

```bash
nix develop --command bash -c 'cargo clippy --version'
```

**Expected output:** `clippy 0.1.XX (hash YYYY-MM-DD)`. Exit code 0.

**Rationale:** `rust-toolchain.toml` lists `clippy` in `components`.

---

### Test 6: rustfmt is available

**Criterion:** MM-64.AC2.5
**Test type:** Operational — command presence
**What to run:**

```bash
nix develop --command bash -c 'rustfmt --version'
```

**Expected output:** `rustfmt 1.X.XX-stable (hash YYYY-MM-DD)`. Exit code 0.

**Rationale:** `rust-toolchain.toml` lists `rustfmt` in `components`.

---

### Test 7: just is available

**Criterion:** MM-64.AC2.6
**Test type:** Operational — command presence
**What to run:**

```bash
nix develop --command bash -c 'just --version'
```

**Expected output:** `just 1.XX.X`. Exit code 0.

**Rationale:** `devenv.nix` includes `pkgs.just` in the `packages` list.

---

### Test 8: cargo-audit is available

**Criterion:** MM-64.AC2.7
**Test type:** Operational — command presence
**What to run:**

```bash
nix develop --command bash -c 'cargo audit --version'
```

**Expected output:** `cargo-audit X.X.X`. Exit code 0.

**Rationale:** `devenv.nix` includes `pkgs.cargo-audit` in the `packages` list.

---

### Test 9: sqlite3 and dev headers are available

**Criterion:** MM-64.AC2.8
**Test type:** Operational — command presence and pkg-config resolution
**What to run:**

```bash
nix develop --command bash -c '
  set -e
  sqlite3 --version
  pkg-config --libs sqlite3
  echo "OK: sqlite3 runtime and dev headers available"
'
```

**Expected output:** A sqlite3 version string (e.g., `3.XX.X YYYY-MM-DD HH:MM:SS`), followed by linker flags (e.g., `-L/nix/store/.../lib -lsqlite3`), followed by `OK: sqlite3 runtime and dev headers available`. Exit code 0.

**Rationale:** `devenv.nix` includes `pkgs.sqlite` and `pkgs.pkg-config` in the `packages` list. The `LIBSQLITE3_SYS_USE_PKG_CONFIG = "1"` env var tells `libsqlite3-sys` to use pkg-config. This test confirms both the runtime binary and dev headers are resolvable.

---

### Test 10: .envrc is tracked by git and contains `use flake`

**Criterion:** MM-64.AC4.1
**Test type:** Operational — git and file content check
**What to run:**

```bash
git ls-files .envrc | grep -q ".envrc" || { echo "FAIL: .envrc not tracked by git"; exit 1; }
grep -q "use flake" .envrc || { echo "FAIL: .envrc does not contain 'use flake'"; exit 1; }
echo "OK: .envrc tracked and contains 'use flake'"
```

**Expected output:** `OK: .envrc tracked and contains 'use flake'`. Exit code 0.

**Rationale:** Phase 1, Task 4 creates `.envrc` with `use flake`. Phase 1, Task 6 commits it. This test does not require entering the Nix shell — it verifies git state and file content directly.

---

### Test 11: flake.lock is tracked by git

**Criterion:** MM-64.AC5.1
**Test type:** Operational — git check
**What to run:**

```bash
git ls-files flake.lock | grep -q "flake.lock" || { echo "FAIL: flake.lock not tracked by git"; exit 1; }
echo "OK: flake.lock tracked by git"
```

**Expected output:** `OK: flake.lock tracked by git`. Exit code 0.

**Rationale:** Phase 2, Task 1 generates `flake.lock` via `nix develop`. Phase 2, Task 3 commits it. This test confirms the file made it into git.

---

### Test 12: flake.nix defines no packages output

**Criterion:** MM-64.AC6.1
**Test type:** Operational — static file analysis
**What to run:**

```bash
grep -E '^\s*packages\s*=' flake.nix && { echo "FAIL: packages output found in flake.nix"; exit 1; } || echo "OK: no packages output"
```

**Expected output:** `OK: no packages output`. Exit code 0.

**Rationale:** The design explicitly scopes MM-64 to devShells only. Phase 1, Task 1 creates `flake.nix` with only a `devShells` output. This grep confirms no `packages` output was accidentally introduced.

---

### Test 13: flake.nix defines no nixosModules output

**Criterion:** MM-64.AC6.2
**Test type:** Operational — static file analysis
**What to run:**

```bash
grep 'nixosModules' flake.nix && { echo "FAIL: nixosModules found in flake.nix"; exit 1; } || echo "OK: no nixosModules"
```

**Expected output:** `OK: no nixosModules`. Exit code 0.

**Rationale:** Same scope boundary as AC6.1. NixOS modules are explicitly out of scope for MM-64. This grep confirms the absence.

---

### Combined Automated Test Script

All automated tests above can be run sequentially as a single validation script. The script should be executed from the repo root after both Phase 1 and Phase 2 are complete.

```bash
#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0

run_test() {
  local name="$1"
  shift
  echo "--- $name ---"
  if "$@"; then
    echo "PASS: $name"
    ((PASS++))
  else
    echo "FAIL: $name"
    ((FAIL++))
  fi
  echo
}

# Tests that do not require the Nix shell
run_test "AC4.1: .envrc tracked with use flake" bash -c '
  git ls-files .envrc | grep -q ".envrc" && grep -q "use flake" .envrc
'

run_test "AC5.1: flake.lock tracked by git" bash -c '
  git ls-files flake.lock | grep -q "flake.lock"
'

run_test "AC6.1: no packages output" bash -c '
  ! grep -qE "^\s*packages\s*=" flake.nix
'

run_test "AC6.2: no nixosModules output" bash -c '
  ! grep -q "nixosModules" flake.nix
'

# Tests that require the Nix shell
run_test "AC1.1: dev shell activates" \
  nix develop --command bash -c 'echo "shell activated"'

run_test "AC2.1+AC3.1: rustc is stable" \
  nix develop --command bash -c '
    V=$(rustc --version)
    echo "$V"
    echo "$V" | grep -qv nightly && echo "$V" | grep -qv beta
  '

run_test "AC2.2: cargo available" \
  nix develop --command bash -c 'cargo --version'

run_test "AC2.3: rust-analyzer available" \
  nix develop --command bash -c 'rust-analyzer --version'

run_test "AC2.4: clippy available" \
  nix develop --command bash -c 'cargo clippy --version'

run_test "AC2.5: rustfmt available" \
  nix develop --command bash -c 'rustfmt --version'

run_test "AC2.6: just available" \
  nix develop --command bash -c 'just --version'

run_test "AC2.7: cargo-audit available" \
  nix develop --command bash -c 'cargo audit --version'

run_test "AC2.8: sqlite3 + pkg-config" \
  nix develop --command bash -c 'sqlite3 --version && pkg-config --libs sqlite3'

echo "========================="
echo "PASS: $PASS  FAIL: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
```

---

## Human Verification

The following acceptance criteria cannot be fully automated on the local development machine. Each includes justification and a verification approach.

### HV-1: Dev shell activates on Linux (x86_64-linux)

**Criterion:** MM-64.AC1.2
**Why it cannot be automated locally:** The local development machine is macOS (darwin). Verifying `nix develop` on `x86_64-linux` requires either a Linux machine or a Linux CI runner. The flake declares support for all systems returned by `nix-systems/default` (including `x86_64-linux`), but the Nix evaluation and package availability can only be confirmed by actually running on that platform.

**Verification approach:**
1. A contributor with access to a `x86_64-linux` machine clones the repo and runs:
   ```bash
   nix develop --command bash -c 'rustc --version && echo "Linux shell OK"'
   ```
2. Alternatively, a CI pipeline (e.g., GitHub Actions with `ubuntu-latest` and Nix installed) runs the combined automated test script above.
3. Pass condition: exit code 0 and `Linux shell OK` printed.

---

### HV-2: rustup reads rust-toolchain.toml without Nix

**Criterion:** MM-64.AC3.2
**Why it cannot be automated locally:** This test must run *outside* the Nix shell on a machine with `rustup` installed. The automated test harness runs inside `nix develop --command`, which sets up the Nix-managed toolchain and shadows rustup. Testing rustup's behavior requires a deliberate exit from the Nix environment, which conflicts with the automated test runner's context.

**Verification approach:**
1. Ensure rustup is installed on the machine (outside Nix).
2. From the repo root, without entering the Nix shell, run:
   ```bash
   rustup show
   ```
3. Pass condition: output includes a line referencing `stable` and showing the same major.minor Rust version as `rustc --version` inside the Nix shell. The `rust-toolchain.toml` file should appear in the output as the active override source.

---

### HV-3: direnv activates the shell automatically on `cd`

**Criterion:** MM-64.AC4.2
**Why it cannot be automated locally:** direnv activation is a shell-level integration that requires an interactive shell session with direnv hooked in (e.g., `eval "$(direnv hook zsh)"` in `.zshrc`). Non-interactive `bash -c` invocations do not load the direnv hook, so the automatic activation on `cd` cannot be observed programmatically.

**Verification approach:**
1. Ensure direnv is installed and hooked into the shell (`eval "$(direnv hook zsh)"` or equivalent in shell RC file).
2. From the repo root, run:
   ```bash
   direnv allow
   ```
3. `cd` out of the repo directory, then `cd` back in.
4. Pass condition: direnv prints a loading/activation message, and `which rustc` points to a path inside `/nix/store/` (confirming the devShell is active).

---

## Acceptance Criteria Traceability Matrix

| Criterion | Description | Test Type | Test ID |
|-----------|-------------|-----------|---------|
| MM-64.AC1.1 | `nix develop` succeeds on macOS | Automated | Test 1 |
| MM-64.AC1.2 | `nix develop` succeeds on Linux | Human | HV-1 |
| MM-64.AC2.1 | `rustc` is stable | Automated | Test 2 |
| MM-64.AC2.2 | `cargo` available | Automated | Test 3 |
| MM-64.AC2.3 | `rust-analyzer` available | Automated | Test 4 |
| MM-64.AC2.4 | `clippy` available | Automated | Test 5 |
| MM-64.AC2.5 | `rustfmt` available | Automated | Test 6 |
| MM-64.AC2.6 | `just` available | Automated | Test 7 |
| MM-64.AC2.7 | `cargo-audit` available | Automated | Test 8 |
| MM-64.AC2.8 | `sqlite3` + pkg-config headers | Automated | Test 9 |
| MM-64.AC3.1 | Rust version matches rust-toolchain.toml stable | Automated | Test 2 |
| MM-64.AC3.2 | rustup reads rust-toolchain.toml without Nix | Human | HV-2 |
| MM-64.AC4.1 | `.envrc` tracked with `use flake` | Automated | Test 10 |
| MM-64.AC4.2 | `direnv allow` activates shell on `cd` | Human | HV-3 |
| MM-64.AC5.1 | `flake.lock` tracked by git | Automated | Test 11 |
| MM-64.AC6.1 | No `packages` output in flake.nix | Automated | Test 12 |
| MM-64.AC6.2 | No `nixosModules` output in flake.nix | Automated | Test 13 |
