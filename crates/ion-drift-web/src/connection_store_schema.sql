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

-- Port summary by direction
CREATE INDEX IF NOT EXISTS idx_ch_port_direction
    ON connection_history(first_seen, dst_port, dst_is_external, src_vlan)
    WHERE dst_port IS NOT NULL;

-- Retention pruning
CREATE INDEX IF NOT EXISTS idx_ch_prune
    ON connection_history(last_seen, closed) WHERE closed = 1;

-- Port flow baselines for anomaly detection

CREATE TABLE IF NOT EXISTS port_flow_baseline (
    id INTEGER PRIMARY KEY,
    flow_direction TEXT NOT NULL,          -- 'outbound', 'internal'
    protocol TEXT NOT NULL,                -- 'tcp', 'udp', 'icmp'
    dst_port INTEGER NOT NULL,
    service_name TEXT,                     -- 'HTTPS', 'SSH', 'DNS', etc.

    -- Baseline metrics (computed from last 7 days)
    avg_bytes_per_day INTEGER NOT NULL,
    max_bytes_per_day INTEGER NOT NULL,
    avg_connections_per_day INTEGER NOT NULL,
    max_connections_per_day INTEGER NOT NULL,
    days_present INTEGER NOT NULL,         -- out of 7, how many days this port appeared

    -- Source context
    typical_sources TEXT,                  -- JSON array of src_ips/VLANs
    typical_destinations TEXT,             -- JSON array of dst_ips

    computed_at TEXT NOT NULL              -- ISO 8601
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pfb_lookup
    ON port_flow_baseline(flow_direction, protocol, dst_port);

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

-- Anomaly cross-reference links (bridges behavior.db device anomalies with port flow anomalies)

CREATE TABLE IF NOT EXISTS anomaly_links (
    id INTEGER PRIMARY KEY,

    -- Port flow side
    port_anomaly_type TEXT NOT NULL,       -- 'new_port', 'volume_spike', 'source_anomaly'
    flow_direction TEXT NOT NULL,           -- 'outbound', 'inbound', 'internal'
    protocol TEXT NOT NULL,
    dst_port INTEGER NOT NULL,

    -- Device side
    device_mac TEXT NOT NULL,
    device_ip TEXT NOT NULL,
    device_vlan TEXT,
    device_hostname TEXT,
    behavior_anomaly_id INTEGER,           -- ID from behavior.db anomalies table

    -- Classification
    correlated INTEGER NOT NULL DEFAULT 0, -- 1 if both engines flagged independently
    source TEXT NOT NULL,                   -- 'port_flow', 'behavior', 'both'
    severity TEXT NOT NULL,                 -- 'critical', 'warning', 'info'

    -- Context
    device_bytes INTEGER DEFAULT 0,
    device_connections INTEGER DEFAULT 0,
    port_is_baselined INTEGER NOT NULL,
    port_days_in_baseline INTEGER DEFAULT 0,

    -- Lifecycle
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT                        -- 'user', 'auto'
);

CREATE INDEX IF NOT EXISTS idx_al_port
    ON anomaly_links(protocol, dst_port, flow_direction);
CREATE INDEX IF NOT EXISTS idx_al_device
    ON anomaly_links(device_mac);
CREATE INDEX IF NOT EXISTS idx_al_behavior
    ON anomaly_links(behavior_anomaly_id) WHERE behavior_anomaly_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_al_unresolved
    ON anomaly_links(resolved_at) WHERE resolved_at IS NULL;
