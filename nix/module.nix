{ lib, config, ... }:

let cfg = config.services.ezpds;
in
{
  options.services.ezpds = {
    enable = lib.mkEnableOption "ezpds PDS (OCI container)";

    image = lib.mkOption {
      type = lib.types.str;
      description = "PDS OCI image reference, ideally digest-pinned (ghcr.io/<owner>/pds@sha256:...).";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Host port to publish.";
    };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/ezpds";
      description = "Host dir bind-mounted to the container's /data.";
    };

    publicUrl = lib.mkOption {
      type = lib.types.str;
      description = "Public https URL of the PDS.";
    };

    availableUserDomains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      description = "Allowed handle domains.";
    };

    reservedHandles = lib.mkOption {
      type = lib.types.nullOr (lib.types.listOf lib.types.str);
      default = null;
      description = ''
        Handle names (first DNS label) that may never be claimed under a served
        domain — infrastructure hostnames in the user-handle wildcard space.
        `null` (the default) keeps the server's built-in defaults
        (`identitywallet`, `about`); an explicit list replaces them, and `[]`
        reserves nothing.
      '';
    };

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
      } // lib.optionalAttrs (cfg.reservedHandles != null) {
        # Only emit when explicitly set: an unset option keeps the server defaults,
        # while an empty list (→ "") deliberately reserves nothing.
        EZPDS_RESERVED_HANDLES = lib.concatStringsSep "," cfg.reservedHandles;
      };
      environmentFiles = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
    };

    systemd.tmpfiles.rules = [ "d ${cfg.dataDir} 0750 root root - -" ];

    # Preserve hardening intent: the container already runs non-root (relay uid 10001, baked in Phase 2).
    # Carry NoNewPrivileges onto the generated unit where applicable.
    systemd.services."${config.virtualisation.oci-containers.backend}-ezpds".serviceConfig.NoNewPrivileges = true;
  };
}
