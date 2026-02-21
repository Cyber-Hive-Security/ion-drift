#!/bin/sh
# Fix data directory ownership for volumes created before non-root migration.
chown -R app:app /app/data 2>/dev/null || true
exec gosu app "$@"
