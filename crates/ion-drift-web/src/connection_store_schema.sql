-- Connection history schema

CREATE TABLE IF NOT EXISTS connection_history (
    id INTEGER PRIMARY KEY,

    -- Flow identity
    conntrack_id TEXT,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,

    -- Source/destination context
    src_mac TEXT,
    src_vlan TEXT,
    src_hostname TEXT,
    dst_vlan TEXT,
    dst_hostname TEXT,

    -- Lifecycle
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    closed INTEGER NOT NULL DEFAULT 0,
    last_state TEXT,
    duration_seconds INTEGER,

    -- Traffic counters
    bytes_tx INTEGER NOT NULL DEFAULT 0,
    bytes_rx INTEGER NOT NULL DEFAULT 0,

    -- Observation metadata
    data_source TEXT NOT NULL DEFAULT 'poll',
    poll_count INTEGER DEFAULT 0,

    -- GeoIP enrichment
    dst_is_external INTEGER NOT NULL DEFAULT 0,
    geo_country_code TEXT,
    geo_country TEXT,
    geo_city TEXT,
    geo_asn INTEGER,
    geo_org TEXT,
    geo_lat REAL,
    geo_lon REAL,

    -- Anomaly linkage
    flagged INTEGER NOT NULL DEFAULT 0,
    anomaly_id INTEGER
);

-- Primary lookup: find open row for a conntrack ID
CREATE INDEX IF NOT EXISTS idx_ch_conntrack
    ON connection_history(conntrack_id) WHERE conntrack_id IS NOT NULL AND closed = 0;

-- Dedup fallback: find open row by flow tuple (for syslog merging)
CREATE INDEX IF NOT EXISTS idx_ch_flow
    ON connection_history(protocol, src_ip, dst_ip, dst_port) WHERE closed = 0;

-- Time-range queries
CREATE INDEX IF NOT EXISTS idx_ch_first_seen
    ON connection_history(first_seen);

CREATE INDEX IF NOT EXISTS idx_ch_last_seen
    ON connection_history(last_seen);

-- World map aggregation
CREATE INDEX IF NOT EXISTS idx_ch_geo
    ON connection_history(geo_country_code, first_seen) WHERE dst_is_external = 1;

-- Per-source queries
CREATE INDEX IF NOT EXISTS idx_ch_src
    ON connection_history(src_ip, first_seen);

-- Flagged connections
CREATE INDEX IF NOT EXISTS idx_ch_flagged
    ON connection_history(flagged) WHERE flagged = 1;

-- Retention pruning
CREATE INDEX IF NOT EXISTS idx_ch_prune
    ON connection_history(last_seen, closed) WHERE closed = 1;

-- Weekly snapshots

CREATE TABLE IF NOT EXISTS weekly_snapshots (
    id INTEGER PRIMARY KEY,
    snapshot_week TEXT NOT NULL,
    snapshot_type TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    data TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_snap_week_type
    ON weekly_snapshots(snapshot_week, snapshot_type);
