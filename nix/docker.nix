{ pkgs, relay }:
pkgs.dockerTools.buildLayeredImage {
  name = "relay";
  tag = "latest";
  contents = [
    relay
    pkgs.sqlite.out  # runtime shared library only; .out excludes headers/dev outputs
    pkgs.cacert
    pkgs.tzdata
  ];
  config = {
    Entrypoint = [ "${relay}/bin/relay" ];
    Env = [
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      "TZDIR=${pkgs.tzdata}/share/zoneinfo"
    ];
  };
}
