#!/bin/sh
set -e
# Railway Volumes (and any fresh host mount) are root:root on first use.
# Fix /data ownership before dropping to the relay user.
chown relay:relay /data

if [ -n "${LITESTREAM_REPLICA_URL:-}" ]; then
  # Production: restore the DB from the replica if it's missing, then run the
  # relay under Litestream so the WAL is streamed continuously to object storage.
  gosu relay litestream restore -if-db-not-exists -if-replica-exists -config /etc/litestream.yml /data/relay.db
  exec gosu relay litestream replicate -config /etc/litestream.yml -exec "/usr/local/bin/relay"
else
  # No replica configured (staging/local): original behavior, unchanged.
  exec gosu relay /usr/local/bin/relay
fi
