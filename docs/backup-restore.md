# Backup and Restore

Everything Ion Drift persists lives in one directory — the data volume. Back that
up and you can rebuild a server from nothing.

## What's in the data volume

The container writes to `XDG_DATA_HOME=/app/data`, so all state is under
`/app/data/ion-drift/` (the `ion-drift-data` volume in the example compose file):

| File | Contents | Loss impact |
|---|---|---|
| `secrets.db` | Encrypted router credentials, OIDC secret, session secret, license key, registered modules | Re-enter credentials and license key |
| `switch.db` | Network identities, switch state, topology data | Re-learned over hours/days |
| `behavior.db` | Device behavior baselines and observations | Baselines rebuild over the 7-day learning period |
| `connections.db` | Connection history | Historical data, not recoverable |
| `traffic.db`, `metrics.db`, `stats.db` | Traffic/metric history, usage stats | Historical data, not recoverable |
| `findings.db` | Module-emitted findings and lifecycle state | Open findings re-emitted by modules |
| `sessions.db` | Login sessions | Users log in again |
| `geo.db` | GeoIP lookup cache | Rebuilt automatically |
| `geoip/` | GeoIP databases | **No backup needed** — reseeded from the image on every start |
| KEK cache | Encrypted local copy of the key-encryption key (mTLS/Keycloak installs) | Re-bootstrapped from Keycloak on next start |

## Backing up

SQLite databases must not be copied while the server is writing to them — a
mid-write copy can be corrupt. Two safe options:

### Option A — stop, copy, start (simplest)

```bash
docker compose stop ion-drift
docker run --rm -v ion-drift-data:/data -v "$(pwd)":/backup alpine \
  tar czf /backup/ion-drift-backup-$(date +%Y%m%d).tar.gz -C /data .
docker compose start ion-drift
```

Downtime is a few seconds. For a homelab or single-site install this is the
recommended path — put it in cron during a quiet hour.

### Option B — online backup (no downtime)

Use SQLite's backup API against each database file via the `sqlite3` CLI:

```bash
docker exec ion-drift sh -c \
  'for db in /app/data/ion-drift/*.db; do
     sqlite3 "$db" ".backup ${db%.db}.bak"
   done'
docker cp ion-drift:/app/data/ion-drift/ ./backup-staging/
docker exec ion-drift sh -c 'rm /app/data/ion-drift/*.bak'
```

`.backup` takes a consistent snapshot even while the server runs.

## Restoring

1. Stop the container: `docker compose stop ion-drift`
2. Restore the archive into the volume:

```bash
docker run --rm -v ion-drift-data:/data -v "$(pwd)":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/ion-drift-backup-YYYYMMDD.tar.gz -C /data'
```

3. Start it: `docker compose start ion-drift`

The server runs its schema migrations on start, so restoring a backup made by an
**older** version into a **newer** image is supported. The reverse — pointing an
older image at data written by a newer version — is not; restore with the same or
a newer image than the one that wrote the backup.

### Restoring to a different host

The volume is self-contained with one caveat: on mTLS/Keycloak installs,
`secrets.db` is encrypted with a KEK held in Keycloak (with an encrypted local
cache in the data dir). The new host must be able to reach Keycloak with the same
client credentials to decrypt it. Local-auth installs have no external dependency.

## Before every upgrade

Take an Option A backup before pulling a new image. Upgrades migrate the schema
forward automatically; the backup is your path back if you need to return to the
previous version (downgrades require restoring the matching backup — see above).
