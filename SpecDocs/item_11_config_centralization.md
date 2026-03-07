# Problem Fix Item 11 — Centralize Runtime Config Schema

## Priority: P1 | Difficulty: M | Safe for AI: Yes | Needs human review: Yes

## Problem

Runtime configuration is spread across:
- `crates/ion-drift-web/src/config.rs` — TOML-based `ServerConfig` with env var overlays
- `crates/ion-drift-cli/src/config.rs` — separate CLI config with duplicated defaults
- `crates/mikrotik-core/src/client.rs` — `DEFAULT_ROUTER_HOST`, `DEFAULT_ROUTER_PORT`, `DEFAULT_ROUTER_USERNAME` constants
- 3 env vars loaded in `main.rs`: `HIVE_ROUTER_PASSWORD`, `HIVE_ROUTER_OIDC_SECRET`, `HIVE_ROUTER_SESSION_SECRET`
- `config/server.example.toml`, `config/production.toml`, `config/cli.example.toml` — templates that may drift from code

There is no single source of truth that documents all config keys, their types, defaults, and whether they're required.

## Goal

1. Every config key documented in one place with its type, default, required/optional status, and env var override (if any)
2. Example TOML generated or verified from that source of truth
3. No behavior changes — this is a documentation and structural improvement

## Scope

### 1. Add config reference doc

Create `docs/configuration.md` with a complete table of every config key:

```markdown
| TOML Key | Type | Default | Env Override | Required | Description |
|----------|------|---------|-------------|----------|-------------|
| server.listen_addr | string | 0.0.0.0 | — | No | ... |
| server.listen_port | u16 | 3000 | — | No | ... |
| router.host | string | 192.168.88.1 | — | No | ... |
| router.password | — | — | HIVE_ROUTER_PASSWORD | Yes | ... |
...
```

Source this table from reading `config.rs` — every struct field, every `#[serde(default)]`, every `#[serde(skip)]` field that's loaded from env.

### 2. Add startup config dump

In `main.rs`, after config is loaded and env vars are applied, add a `tracing::info!` block that logs the resolved config (with secrets redacted):

```rust
tracing::info!(
    listen = %config.server.listen_addr,
    port = config.server.listen_port,
    router_host = %config.router.host,
    router_port = config.router.port,
    tls = config.router.tls,
    wan_interface = %config.router.wan_interface,
    oidc_issuer = %config.oidc.issuer_url,
    session_max_age = config.session.max_age_seconds,
    syslog_port = config.syslog.port,
    "resolved configuration"
);
```

### 3. Validate config/server.example.toml matches code

Write a check (can be a comment block or a test) that every key in `ServerConfig` appears in the example TOML. This prevents silent drift.

### 4. Add `--dump-config` CLI flag to ion-drift-web

Add a `--dump-config` argument that prints the resolved config (with secrets masked) as TOML and exits. Useful for debugging deployment issues.

## Key files

| File | Action |
|------|--------|
| `docs/configuration.md` | NEW — complete config reference |
| `crates/ion-drift-web/src/main.rs` | Add config dump log + `--dump-config` flag |
| `config/server.example.toml` | Verify/update to match all keys |
| `config/cli.example.toml` | Verify/update to match all keys |

## Constraints

- Do NOT restructure the config structs — just document what exists
- Do NOT add new env var overrides unless a key is genuinely missing one
- Do NOT change default values
- The `docs/configuration.md` should be hand-readable, not auto-generated

## Verification

1. `cargo check --workspace` passes
2. `docs/configuration.md` lists every field from `ServerConfig` and CLI config
3. `config/server.example.toml` has a comment for every section and key
4. `--dump-config` prints valid TOML with secrets masked
