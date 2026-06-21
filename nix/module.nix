{ lib, config, ... }:

let cfg = config.services.ezpds;
in
{
  options.services.ezpds = {
    enable = lib.mkEnableOption "ezpds relay (OCI container)";

    image = lib.mkOption {
      type = lib.types.str;
      description = "Relay OCI image reference, ideally digest-pinned (ghcr.io/<owner>/relay@sha256:...).";
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
      description = "Public https URL of the relay.";
    };

    availableUserDomains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      description = "Allowed handle domains.";
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
      };
      environmentFiles = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
    };

    systemd.tmpfiles.rules = [ "d ${cfg.dataDir} 0750 root root - -" ];

    # Preserve hardening intent: the container already runs non-root (relay uid 10001, baked in Phase 2).
    # Carry NoNewPrivileges onto the generated unit where applicable.
    systemd.services."${config.virtualisation.oci-containers.backend}-ezpds".serviceConfig.NoNewPrivileges = true;
  };
}
