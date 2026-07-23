//! Versioned schema migrations over SQLite's `PRAGMA user_version`.
//!
//! Adoption model (see docs/backup-restore.md for the operator-facing contract):
//!
//! 1. Each store calls [`open_guard`] right after opening its connection. If the
//!    database was written by a NEWER schema version than this binary knows,
//!    opening fails loudly instead of corrupting data — running an old image
//!    against new data is the one unrecoverable direction.
//! 2. The store runs its baseline init (the long-standing idempotent
//!    `CREATE TABLE IF NOT EXISTS` + guarded `ALTER` flow). Databases that
//!    predate version stamping (`user_version == 0`) are upgraded by exactly
//!    this path, unchanged.
//! 3. Migrations introduced AFTER version stamping go through
//!    [`apply_versioned`] as `(version, sql)` steps — run once, in order, each
//!    in its own transaction, instead of growing the idempotent pile.
//! 4. The store calls [`stamp`] with its `SCHEMA_VERSION` at the end of init.
//!
//! To add a future migration to a store: bump its `SCHEMA_VERSION` constant and
//! append a `(new_version, sql)` step to its `apply_versioned` call. Do NOT
//! edit the baseline for already-shipped schema changes.

use rusqlite::Connection;

/// Read the database's stamped schema version and refuse to open data written
/// by a newer schema. Returns the current on-disk version (0 = pre-versioning
/// or fresh database).
pub fn open_guard(conn: &Connection, domain: &str, code_version: u32) -> Result<u32, String> {
    let db_version: u32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| format!("{domain}: failed to read schema version: {e}"))?;
    if db_version > code_version {
        return Err(format!(
            "{domain}: database schema version {db_version} is newer than this \
             binary supports ({code_version}). This data was written by a newer \
             Ion Drift release — upgrade the image, or restore the backup taken \
             before the upgrade. Refusing to open to avoid data corruption."
        ));
    }
    Ok(db_version)
}

/// Apply versioned migration steps strictly greater than `db_version`, in
/// ascending order. Each step runs in its own transaction and bumps
/// `user_version` on success, so a failure leaves the database resumable at
/// the last completed step.
pub fn apply_versioned(
    conn: &mut Connection,
    domain: &str,
    db_version: u32,
    steps: &[(u32, &str)],
) -> Result<(), String> {
    debug_assert!(
        steps.windows(2).all(|w| w[0].0 < w[1].0),
        "{domain}: migration steps must be in strictly ascending version order"
    );
    for (version, sql) in steps {
        if *version <= db_version {
            continue;
        }
        let tx = conn
            .transaction()
            .map_err(|e| format!("{domain}: begin migration v{version}: {e}"))?;
        tx.execute_batch(sql)
            .map_err(|e| format!("{domain}: migration v{version} failed: {e}"))?;
        tx.pragma_update(None, "user_version", version)
            .map_err(|e| format!("{domain}: stamp v{version}: {e}"))?;
        tx.commit()
            .map_err(|e| format!("{domain}: commit migration v{version}: {e}"))?;
        tracing::info!(domain, version, "applied schema migration");
    }
    Ok(())
}

/// Stamp the schema version after baseline init. Called at the end of a
/// store's constructor so a failed init never stamps.
pub fn stamp(conn: &Connection, domain: &str, version: u32) -> Result<(), String> {
    conn.pragma_update(None, "user_version", version)
        .map_err(|e| format!("{domain}: failed to stamp schema version {version}: {e}"))
}

/// Adapter for stores whose constructors return `rusqlite::Error` rather than
/// `String` — preserves the message in the `SqliteFailure` payload.
pub fn to_sqlite_err(msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
        Some(msg),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        Connection::open_in_memory().expect("in-memory db")
    }

    #[test]
    fn fresh_db_reports_version_zero() {
        let conn = mem();
        assert_eq!(open_guard(&conn, "test", 5).expect("guard"), 0);
    }

    #[test]
    fn guard_refuses_newer_database() {
        let conn = mem();
        conn.pragma_update(None, "user_version", 9).expect("set");
        let err = open_guard(&conn, "test", 3).expect_err("must refuse");
        assert!(err.contains("newer than this binary"), "got: {err}");
    }

    #[test]
    fn guard_allows_equal_and_older() {
        let conn = mem();
        conn.pragma_update(None, "user_version", 3).expect("set");
        assert_eq!(open_guard(&conn, "test", 3).expect("equal ok"), 3);
        assert_eq!(open_guard(&conn, "test", 4).expect("older ok"), 3);
    }

    #[test]
    fn versioned_steps_apply_once_in_order() {
        let mut conn = mem();
        let steps: &[(u32, &str)] = &[
            (1, "CREATE TABLE t (a INTEGER);"),
            (2, "ALTER TABLE t ADD COLUMN b INTEGER;"),
        ];
        apply_versioned(&mut conn, "test", 0, steps).expect("apply");
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("version");
        assert_eq!(v, 2);
        // Re-applying from the stamped version is a no-op (would error on
        // duplicate column if steps re-ran).
        apply_versioned(&mut conn, "test", v, steps).expect("idempotent");
    }

    #[test]
    fn failed_step_preserves_prior_progress() {
        let mut conn = mem();
        let steps: &[(u32, &str)] = &[
            (1, "CREATE TABLE t (a INTEGER);"),
            (2, "THIS IS NOT SQL;"),
        ];
        let err = apply_versioned(&mut conn, "test", 0, steps).expect_err("must fail");
        assert!(err.contains("migration v2"), "got: {err}");
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("version");
        assert_eq!(v, 1, "v1 committed, v2 rolled back");
    }
}
