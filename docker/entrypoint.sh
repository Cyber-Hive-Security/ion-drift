#!/bin/sh
# Fix data directory ownership for volumes created before non-root migration.
chown -R app:app /app/data 2>/dev/null || true
chmod 700 /app/data 2>/dev/null || true
find /app/data -name "*.db" -exec chmod 600 {} \; 2>/dev/null || true
exec gosu app "$@"
