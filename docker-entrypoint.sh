#!/bin/sh
# Fix /data ownership for the bind-mounted volume (whatever host UID owns
# it), then drop from root to the unprivileged certmgr user before exec'ing
# the real command (gunicorn or certmgr).
set -e

if [ "$(id -u)" = "0" ]; then
    mkdir -p /data
    chown -R certmgr:certmgr /data
    exec gosu certmgr "$@"
fi

exec "$@"
