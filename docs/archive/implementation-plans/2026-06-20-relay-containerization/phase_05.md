# Relay Containerization — Phase 5: NixOS via oci-containers + flake cleanup

**Goal:** The NixOS lab host runs the *same* image through `virtualisation.oci-containers` (colmena still deploys), and the Nix-native relay build (crane + `nix/docker.nix`) is retired.

**Architecture:** Publish the image to GHCR; rework `nix/module.nix` so `services.ezpds` runs the OCI image as a systemd-managed container with the secret injected via `environmentFiles` (agenix/sops); strip the crane build, `docker-image` output, and `nix/docker.nix` from the flake while keeping `devShells` and `nixosModules.default`.

**Tech Stack:** GHCR, NixOS `virtualisation.oci-containers` (podman/docker backend), agenix/sops-nix, colmena.

**Scope:** Phase 5 of 6.

**Codebase verified:** 2026-06-20.

> **Verified anchors:** `nix/module.nix` (full module, systemd service at `:98-120`, options `:22-87`); `flake.nix` crane build (`rustToolchain:29`, `commonArgs:32-39`, `cargoArtifacts:46-48`, `relay:50-53`, `packages` outputs `:54-59`, `docker-image:58`, `nixosModules.default` sets `services.ezpds.package` `:81-83`); `nix/docker.nix` (Nix image builder).
>
> **Platform note:** image publish is **[requires Docker + GHCR auth]**; module/flake edits are authored anywhere; `nix flake check` is **[requires Nix]**; the colmena deploy + health check is **[NixOS lab host only]**. Image distribution = **GHCR (Option A)** per the design decision.

---

## Acceptance Criteria Coverage

### relay-containerization.AC4
- **relay-containerization.AC4.1 Success:** `nix/module.nix` runs the relay as a `virtualisation.oci-containers` service; a colmena deploy to the lab host serves `/xrpc/_health`.
- **relay-containerization.AC4.2 Success:** the secret is injected via `environmentFiles` (agenix/sops-nix), not stored in the Nix store.
- **relay-containerization.AC4.3 Success:** the crane `relay` build and the `docker-image`/`nix/docker.nix` output are removed or deprecated; `nix flake check` passes; `devShells` and `nixosModules.default` still evaluate.

**Verifies (this phase):** AC4.1 (lab host), AC4.2, AC4.3. Infrastructure — `nix flake check` + colmena operational verification.

---

<!-- START_TASK_1 -->
### Task 1: Publish the image to GHCR [requires Docker + GHCR auth]

**Files:** optional — `.github/workflows/publish-relay.yml` (only if you want CI publishing; there is no CI today).

**Step 1: Tag + push manually** (sufficient for a solo/experimental setup):
```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <github-user> --password-stdin
docker build -t ghcr.io/<owner>/relay:<tag> .
docker push ghcr.io/<owner>/relay:<tag>
# Capture the pushed digest for digest-pinned consumption:
docker buildx imagetools inspect ghcr.io/<owner>/relay:<tag> | grep -i digest | head -1
```

**Step 2 (optional):** if you'd rather automate, add a minimal GH Action (`.github/workflows/publish-relay.yml`) that builds and pushes to GHCR on tag/release. Keep it out of scope if you prefer manual pushes for now — note the choice in the deploy doc (Phase 6).

**Outcome:** a `ghcr.io/<owner>/relay@sha256:<digest>` reference the NixOS host can pull.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Rework `nix/module.nix` to run the OCI image

**Files:**
- Modify: `nix/module.nix` (replace the binary/systemd service with an `oci-containers` container)

**Step 1:** Replace the module so `services.ezpds` runs the published image. Target shape (adapt option names to taste; keep the secret out of the Nix store via `environmentFiles`):
```nix
{ lib, config, ... }:
let cfg = config.services.ezpds;
in {
  options.services.ezpds = {
    enable = lib.mkEnableOption "ezpds relay (OCI container)";

    image = lib.mkOption {
      type = lib.types.str;
      description = "Relay OCI image reference, ideally digest-pinned (ghcr.io/<owner>/relay@sha256:...).";
    };

    port = lib.mkOption { type = lib.types.port; default = 8080; description = "Host port to publish."; };
    dataDir = lib.mkOption { type = lib.types.str; default = "/var/lib/ezpds"; description = "Host dir bind-mounted to the container's /data."; };
    publicUrl = lib.mkOption { type = lib.types.str; description = "Public https URL of the relay."; };
    availableUserDomains = lib.mkOption { type = lib.types.listOf lib.types.str; description = "Allowed handle domains."; };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to an env file (from agenix/sops-nix) holding secrets, e.g.
        EZPDS_SIGNING_KEY_MASTER_KEY=... and EZPDS_ADMIN_TOKEN=...
        Keeps secrets out of the world-readable Nix store.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # The host must enable a backend, e.g.:
    #   virtualisation.oci-containers.backend = "podman";
    #   virtualisation.podman.enable = true;
    virtualisation.oci-containers.containers.ezpds = {
      image = cfg.image;
      ports = [ "${toString cfg.port}:8080" ];
      volumes = [ "${cfg.dataDir}:/data" ];
      environment = {
        EZPDS_PUBLIC_URL = cfg.publicUrl;
        EZPDS_AVAILABLE_USER_DOMAINS = lib.concatStringsSep "," cfg.availableUserDomains;
        EZPDS_DATA_DIR = "/data";
        EZPDS_PORT = "8080";
      };
      environmentFiles = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
    };

    systemd.tmpfiles.rules = [ "d ${cfg.dataDir} 0750 root root - -" ];
  };
}
```

**Step 2:** Note for the host config (document in Phase 6, not enforced by the module): the lab host enables the backend (`virtualisation.oci-containers.backend = "podman"`, `virtualisation.podman.enable = true`) and provides the `environmentFile` via agenix/sops. Colmena pushes this unchanged.

**Step 2b — preserve hardening intent (the old systemd unit had `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, `PrivateTmp`, dedicated `ezpds` user):** under `oci-containers` the container already runs **non-root** (`relay` uid 10001, baked in Phase 2). Carry the remaining defense-in-depth onto the generated unit where applicable — e.g. `systemd.services."<backend>-ezpds".serviceConfig.NoNewPrivileges = true;` (backend = `podman`/`docker`) — and rely on container isolation for the rest. Record the final hardening posture in Phase 6's deploy note. Do not silently drop the hardening.

**Step 3: Commit**
```bash
git add nix/module.nix
git commit -m "feat(nix): run relay via virtualisation.oci-containers (drop Nix-built binary)"
```
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Strip the crane build + docker-image output from the flake

**Files:**
- Modify: `flake.nix`
- Delete: `nix/docker.nix`

**Step 1:** In `flake.nix`, remove the crane relay build and the image output:
- Delete `rustToolchain` (`:29`), `craneLib` (`:30`), `commonArgs` (`:32-39`), `cargoArtifacts` (`:46-48`), `relay` (`:50-53`), and the `packages` attrset entries (`relay`, `default`, and the Linux `docker-image` import of `nix/docker.nix`, `:54-59`).
- If `packages` becomes empty, remove the `packages = forEachSystem (...)` output entirely.
- Remove now-unused inputs if desired: `crane`, `rust-overlay` (and their `outputs` args). Optional but tidy.

**Step 2:** Fix `nixosModules.default` (`:75-84`): it currently sets `config.services.ezpds.package = ... self.packages.<system>.relay`. The reworked module has no `package` option — **remove that `config.services.ezpds.package` block**, leaving just `imports = [ ./nix/module.nix ];`. After removing the `self.packages.${pkgs.system}` access, the `{ lib, pkgs, ... }:` args in the `nixosModules.default` head may be unused — drop the now-unused args so `nix flake check` stays lint-clean.

**Step 3:** Remove the Nix image builder and every remaining reference to the deleted outputs:
```bash
git rm nix/docker.nix
# tests/verify-mm66.sh asserts the docker-image output EXISTS and that nix/docker.nix is
# git-tracked — both become false after this cleanup, so the script would hard-fail forever
# (and its `nix eval .#packages...` calls error if the packages output is removed). The
# capability it guarded (conditionally-exposed Nix docker-image) is itself being retired.
git rm tests/verify-mm66.sh
```
Then update `justfile` (the project task runner) — both recipes reference removed outputs:
- `docker-build` (`nix build .#docker-image …`) → repoint to `docker build -t ghcr.io/<owner>/relay:<tag> .`
- `nix-build` (`nix build .#relay`) → delete it (no such output now), or repoint to a `docker build`.
- Leave `nix-check` (`nix flake check …`) unchanged.

**Step 4: Verify the flake still evaluates [requires Nix]:**
```bash
nix flake check --impure --accept-flake-config
nix eval .#nixosModules.default --apply 'm: "ok"' --impure 2>/dev/null || nix flake show
```
Expected: `nix flake check` passes; `devShells.<system>.default` and `nixosModules.default` still resolve; no references remain to the removed `packages.relay`/`docker-image`. (`just nix-check` runs the same `nix flake check`.)

**Step 5: Commit**
```bash
git add flake.nix
git rm --cached nix/docker.nix 2>/dev/null || true
git commit -m "build(nix): retire crane relay build + docker-image output (use Dockerfile/oci-containers)"
```
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Deploy to the lab host via colmena and verify health (AC4.1, AC4.2) [NixOS lab only]

**Files:** none (the host's colmena/flake config — outside this repo — references `nixosModules.default`, sets `services.ezpds.image` to the GHCR digest ref, `publicUrl`, `availableUserDomains`, and `environmentFile` from agenix/sops, and enables a container backend).

**Step 1:** Update the host config to use the new options (image ref + environmentFile), then deploy:
```bash
colmena apply --on <lab-host>
```

**Step 2: Verify (AC4.1):**
```bash
curl -fsS https://<lab-relay-domain>/xrpc/_health && echo
# On the host:
systemctl status podman-ezpds.service   # or docker-ezpds.service depending on backend
```
Expected: 200 + JSON; the container service is active.

**Step 3: Verify the secret isn't in the Nix store (AC4.2):**
```bash
# On the host: the master key must come from the agenix/sops env file, not a store path.
grep -rI "EZPDS_SIGNING_KEY_MASTER_KEY" /nix/store/ 2>/dev/null | head || echo "NOT_IN_STORE"
```
Expected: `NOT_IN_STORE` (the value lives only in the decrypted `environmentFile`, e.g. under `/run/secrets`).
<!-- END_TASK_4 -->

---

## Phase 5 Done When

- The image is on GHCR and the lab host runs it via `oci-containers`; colmena deploy serves `/xrpc/_health` (AC4.1) **[lab host]**.
- The master key is injected via `environmentFiles`, absent from the Nix store (AC4.2).
- `flake.nix` no longer builds the relay via crane and exposes no `docker-image`; `nix/docker.nix` is deleted; `nix flake check` passes; `devShells` + `nixosModules.default` still evaluate (AC4.3).
- All edits committed.
