#!/bin/sh
# Fix data directory ownership for volumes created before non-root migration.
chown -R app:app /app/data 2>/dev/null || true
chmod 700 /app/data 2>/dev/null || true
find /app/data -name "*.db" -exec chmod 600 {} \; 2>/dev/null || true

# Copy mounted certs to a location the app user can read.
# Bind-mounted :ro files may not be readable by the app user.
if [ -d /app/certs ] && ls /app/certs/*.crt >/dev/null 2>&1; then
    mkdir -p /app/data/certs
    cp -f /app/certs/*.crt /app/data/certs/
    chown app:app /app/data/certs/*.crt
    chmod 644 /app/data/certs/*.crt
fi

exec gosu app "$@"
