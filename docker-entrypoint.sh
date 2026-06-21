#!/bin/sh
set -e
# Railway Volumes (and any fresh host mount) are root:root on first use.
# Fix /data ownership before dropping to the relay user.
chown relay:relay /data
exec gosu relay /usr/local/bin/relay
