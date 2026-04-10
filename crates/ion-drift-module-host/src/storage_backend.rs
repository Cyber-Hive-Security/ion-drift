//! SQLite-backed implementation of the [`StorageBackend`] trait.
//!
//! Each module gets its own file at `${data_dir}/modules/<name>.db`. Writes
//! are serialized through a `std::sync::Mutex<Connection>` (SQLite is
//! single-writer) and dispatched via `tokio::task::spawn_blocking` so long
//! queries do not stall the tokio runtime.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ion_drift_module_api::storage::{BoxedFuture, Migration, StorageBackend};
use ion_drift_module_api::StorageError;

/// SQLite backend for a single module.
pub struct SqliteBackend {
    conn: Arc<Mutex<rusqlite::Connection>>,
    module_name: String,
}

impl SqliteBackend {
    /// Open (or create) the SQLite file for a module and install the
    /// migration-tracking metadata table.
    pub async fn open(data_dir: PathBuf, module_name: &str) -> Result<Self, StorageError> {
        let modules_dir = data_dir.join("modules");
        tokio::fs::create_dir_all(&modules_dir)
            .await
            .map_err(|e| StorageError::Io(e.to_string()))?;

        let db_path = modules_dir.join(format!("{module_name}.db"));

        // rusqlite::Connection::open is blocking — run on the blocking pool.
        let conn = tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open(&db_path)
                .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            // Bootstrap the migration tracking table.
            conn.execute(
                "CREATE TABLE IF NOT EXISTS __migrations (
                    name TEXT PRIMARY KEY,
                    applied_at INTEGER NOT NULL
                 )",
                [],
            )
            .map_err(|e| StorageError::Sqlite(e.to_string()))?;
            Ok::<_, StorageError>(conn)
        })
        .await
        .map_err(|e| StorageError::Io(format!("spawn_blocking: {e}")))??;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            module_name: module_name.to_string(),
        })
    }
}

impl StorageBackend for SqliteBackend {
    fn write_any(
        &self,
        f: Box<
            dyn FnOnce(
                    &mut rusqlite::Connection,
                ) -> Box<dyn std::any::Any + Send>
                + Send,
        >,
    ) -> BoxedFuture<'_, Result<Box<dyn std::any::Any + Send>, StorageError>> {
        let conn = self.conn.clone();
        Box::pin(async move {
            // Run the closure on the blocking pool so a slow query does not
            // stall the tokio runtime worker thread.
            tokio::task::spawn_blocking(move || {
                let mut guard = conn
                    .lock()
                    .map_err(|_| StorageError::Sqlite("module storage mutex poisoned".into()))?;
                Ok::<_, StorageError>(f(&mut *guard))
            })
            .await
            .map_err(|e| StorageError::Io(format!("spawn_blocking: {e}")))?
        })
    }

    fn run_migrations<'a>(
        &'a self,
        migrations: &'static [Migration],
    ) -> BoxedFuture<'a, Result<(), StorageError>> {
        let conn = self.conn.clone();
        let module_name = self.module_name.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let mut guard = conn
                    .lock()
                    .map_err(|_| StorageError::Sqlite("module storage mutex poisoned".into()))?;
                let tx = guard
                    .transaction()
                    .map_err(|e| StorageError::Sqlite(e.to_string()))?;

                for m in migrations {
                    let already: i64 = tx
                        .query_row(
                            "SELECT COUNT(*) FROM __migrations WHERE name = ?1",
                            [m.name],
                            |r| r.get(0),
                        )
                        .map_err(|e| StorageError::Sqlite(e.to_string()))?;
                    if already > 0 {
                        continue;
                    }

                    tx.execute_batch(m.sql)
                        .map_err(|e| StorageError::Migration {
                            name: m.name.to_string(),
                            reason: e.to_string(),
                        })?;

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    tx.execute(
                        "INSERT INTO __migrations (name, applied_at) VALUES (?1, ?2)",
                        rusqlite::params![m.name, now],
                    )
                    .map_err(|e| StorageError::Sqlite(e.to_string()))?;
                }

                tx.commit()
                    .map_err(|e| StorageError::Sqlite(e.to_string()))?;

                tracing::info!(module = %module_name, "module migrations applied");
                Ok::<_, StorageError>(())
            })
            .await
            .map_err(|e| StorageError::Io(format!("spawn_blocking: {e}")))?
        })
    }
}
