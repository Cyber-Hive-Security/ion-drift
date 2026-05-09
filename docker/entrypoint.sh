#!/bin/sh
# Fix data directory ownership for volumes created before non-root migration.
chown -R app:app /app/data 2>/dev/null || true
chmod 700 /app/data 2>/dev/null || true
find /app/data -name "*.db" -exec chmod 600 {} \; 2>/dev/null || true

# Seed bundled GeoIP databases into the data volume.
# Docker only initializes a named volume from the image on first creation,
# so users who upgrade from a pre-bundling Drift version have an existing
# (empty) volume that shadows files baked into /app/data. We work around
# that by bundling under /app/seed/ (outside the volume mount) and copying
# into /app/data on every start when the target file is missing or empty.
# User-provided MaxMind files (GeoLite2-*.mmdb) are not touched — the
# runtime prefers them over DB-IP Lite when both are present.
if [ -d /app/seed/geoip ]; then
    mkdir -p /app/data/ion-drift/geoip
    for f in dbip-city-lite.mmdb dbip-asn-lite.mmdb; do
        if [ ! -s "/app/data/ion-drift/geoip/$f" ] && [ -s "/app/seed/geoip/$f" ]; then
            if cp "/app/seed/geoip/$f" "/app/data/ion-drift/geoip/$f"; then
                echo "seeded /app/data/ion-drift/geoip/$f from /app/seed/geoip"
            else
                echo "warning: failed to seed $f" >&2
            fi
        fi
    done
    chown -R app:app /app/data/ion-drift/geoip 2>/dev/null || true
fi

# Copy mounted certs to a location the app user can read.
# Bind-mounted :ro files may not be readable by the app user.
if [ -d /app/certs ] && ls /app/certs/*.crt >/dev/null 2>&1; then
    mkdir -p /app/data/certs
    cp -f /app/certs/*.crt /app/data/certs/
    chown app:app /app/data/certs/*.crt
    chmod 644 /app/data/certs/*.crt
fi

exec gosu app "$@"
