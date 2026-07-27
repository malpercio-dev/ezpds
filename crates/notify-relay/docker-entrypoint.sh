#!/bin/sh
# Relay container entrypoint: fix volume ownership, materialize the two secrets the relay
# reads as FILES from environment variables the platform holds, then drop to the relay user.
#
# Why materialize at all: the relay takes its node secret key and its APNs .p8 as file
# paths, but Railway (and most PaaS) hand out secrets as environment variables, not as
# mounted files. Rather than teach the config layer a second delivery mechanism for each
# secret, the container translates once, here, at the platform seam.
set -e

mkdir -p /data
chown relay:relay /data

# The node secret key IS the relay's address: every enrolled instance has it pinned as
# `[notifications] relay = "<node id>"`. The relay will happily generate a fresh one if the
# file is missing — which is exactly the silent failure to avoid, since a re-addressed
# relay looks healthy while every instance quietly stops reaching it. Supplying
# EZPDS_NOTIFY_NODE_SECRET makes the platform's secret store the source of truth, so the
# identity survives a wiped or re-created volume.
if [ -n "${EZPDS_NOTIFY_NODE_SECRET:-}" ]; then
  key_path="${EZPDS_NOTIFY_SECRET_KEY_PATH:-/data/notify-relay-node.key}"
  if [ -f "$key_path" ]; then
    # Refuse to resolve a conflict by guessing: silently overwriting would re-address a
    # relay that is currently working, and silently keeping the file would ignore the
    # secret the operator just set. Both are worse than stopping.
    if [ "$(cat "$key_path")" != "$EZPDS_NOTIFY_NODE_SECRET" ]; then
      echo "error: $key_path holds a different key than EZPDS_NOTIFY_NODE_SECRET." >&2
      echo "       Unset the variable to keep the volume's identity, or delete the file" >&2
      echo "       to adopt the variable's — note that changing it re-addresses the relay" >&2
      echo "       and every enrolled instance must be re-pointed at the new node id." >&2
      exit 1
    fi
  else
    # 0600 from creation, never a wide file narrowed after the fact: identity.rs refuses to
    # load a key readable by group or other, so this also has to be right, not just tidy.
    (umask 077 && printf '%s' "$EZPDS_NOTIFY_NODE_SECRET" > "$key_path")
    chown relay:relay "$key_path"
  fi
fi

# The APNs token-auth key, PEM text in EZPDS_NOTIFY_APNS_KEY_P8 (newlines preserved — paste
# the .p8 verbatim into the platform's secret field). Written under /run rather than /data:
# it is container-local and ephemeral, so Apple's credential is never left behind on a
# volume that outlives the deploy.
if [ -n "${EZPDS_NOTIFY_APNS_KEY_P8:-}" ]; then
  mkdir -p /run/notify-relay
  (umask 077 && printf '%s' "$EZPDS_NOTIFY_APNS_KEY_P8" > /run/notify-relay/apns.p8)
  chown -R relay:relay /run/notify-relay
  # Only default the path — an operator who mounted a real file keeps their own setting.
  export EZPDS_NOTIFY_APNS_KEY_PATH="${EZPDS_NOTIFY_APNS_KEY_PATH:-/run/notify-relay/apns.p8}"
fi

# `mint-code` and any other subcommand pass through, so `railway run` / `docker run <image>
# mint-code --ttl 24h` reaches the same binary with the same config.
exec gosu relay /usr/local/bin/notify-relay "$@"
