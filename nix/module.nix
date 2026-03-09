{ lib, pkgs, config, ... }:

let
  cfg = config.services.ezpds;

  # Build the TOML attrset, omitting database_url when null.
  # When null, the relay binary derives the database path from data_dir.
  settingsToml = lib.filterAttrs (_: v: v != null) {
    inherit (cfg.settings) bind_address port data_dir public_url database_url;
  };

  generatedConfigFile = (pkgs.formats.toml { }).generate "relay.toml" settingsToml;

  # When configFile is set, bypass the Nix-store-generated TOML entirely.
  # This is the escape hatch for secret injection via agenix or sops-nix.
  activeConfigFile =
    if cfg.configFile != null then cfg.configFile else generatedConfigFile;

in
{
  options.services.ezpds = {
    enable = lib.mkEnableOption "ezpds relay server";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The ezpds relay package to use.";
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Path to a relay.toml configuration file.
        When set, all settings.* options are ignored and this path is
        passed directly to --config. Use with agenix or sops-nix to
        keep secrets outside the world-readable Nix store.
      '';
    };

    settings = {
      bind_address = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0";
        description = "IP address to bind the relay HTTP server to.";
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 8080;
        description = "TCP port to bind the relay HTTP server to.";
      };

      data_dir = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/ezpds";
        description = ''
          Path to the relay data directory. Must be writable by the ezpds user.
          Uses lib.types.str (not lib.types.path) to preserve the value as a
          literal string and avoid Nix store coercion of runtime paths.
        '';
      };

      public_url = lib.mkOption {
        type = lib.types.str;
        description = ''
          Public URL where this relay is reachable (e.g. https://relay.example.com).
          Required — Nix evaluation fails if this option is not set.
        '';
      };

      database_url = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          SQLite database URL. When null (the default), the relay derives
          the database path from data_dir. Omitted from the generated
          relay.toml when null.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.ezpds = {
      isSystemUser = true;
      group = "ezpds";
      description = "ezpds relay service user";
    };

    users.groups.ezpds = { };

    systemd.services.ezpds = {
      description = "ezpds relay server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        User = "ezpds";
        Group = "ezpds";
        ExecStart = "${cfg.package}/bin/relay --config ${activeConfigFile}";
        StateDirectory = "ezpds";
        StateDirectoryMode = "0750";
        Restart = "on-failure";
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        NoNewPrivileges = true;
      };
    };
  };
}
