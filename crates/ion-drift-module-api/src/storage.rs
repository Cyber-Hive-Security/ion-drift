//! Per-module isolated storage.
//!
//! Modules that declare [`crate::StorageNeed::Isolated`] receive a
//! [`ModuleStorage`] handle backed by a dedicated SQLite file at
//! `${data_dir}/modules/<name>.db`. The module owns the schema and migrations
//! entirely. Drift core has no knowledge of module tables and no access to
//! the file.
//!
//! The host provisions the file during context build and runs any migrations
//! the module specifies.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::error::StorageError;

/// Boxed future type alias used by the backend trait.
pub type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Isolated storage handle for a single module.
///
/// Cloneable and reference-counted. Internally holds a backend trait object
/// that wraps a SQLite connection with single-writer synchronization.
#[derive(Clone)]
pub struct ModuleStorage {
    inner: Arc<dyn StorageBackend>,
}

impl ModuleStorage {
    /// Construct from a backend implementation. Intended for host use.
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        Self { inner: backend }
    }

    /// Acquire exclusive write access to the underlying connection.
    ///
    /// Runs the provided closure with a locked rusqlite connection. The
    /// closure runs on a blocking-compatible executor so long queries do not
    /// block the tokio runtime.
    pub async fn write<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut rusqlite::Connection) -> Result<R, StorageError> + Send + 'static,
    ) -> Result<R, StorageError> {
        self.inner.write_boxed(Box::new(f)).await
    }

    /// Run the provided migrations in order. Each migration is tracked by
    /// name in a metadata table. Re-running a migration with an existing
    /// name is a no-op.
    pub async fn run_migrations(
        &self,
        migrations: &'static [Migration],
    ) -> Result<(), StorageError> {
        self.inner.run_migrations(migrations).await
    }
}

/// A migration the module wants run against its isolated database.
///
/// Migrations are run in order; each is tracked by `name` in a metadata
/// table. Re-running a migration with an existing name is a no-op.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub name: &'static str,
    pub sql: &'static str,
}

/// Boxed closure type used by the backend's `write_boxed` method.
pub type WriteClosure<R> =
    Box<dyn FnOnce(&mut rusqlite::Connection) -> Result<R, StorageError> + Send>;

/// Backend trait implemented by the host. Not intended for module authors.
///
/// The type-erased closure indirection keeps this trait object-safe so
/// [`ModuleStorage`] can hold `Arc<dyn StorageBackend>`.
pub trait StorageBackend: Send + Sync + 'static {
    /// Execute a closure with a locked connection, returning its result via
    /// a trait-object future.
    ///
    /// The backend takes a boxed closure that returns a boxed Any. The
    /// `ModuleStorage::write` wrapper provides the typed interface.
    fn write_any(
        &self,
        f: Box<
            dyn FnOnce(
                    &mut rusqlite::Connection,
                )
                    -> Box<dyn std::any::Any + Send> + Send,
        >,
    ) -> BoxedFuture<'_, Result<Box<dyn std::any::Any + Send>, StorageError>>;

    fn run_migrations<'a>(
        &'a self,
        migrations: &'static [Migration],
    ) -> BoxedFuture<'a, Result<(), StorageError>>;
}

// Blanket helper that the write_boxed wrapper uses — converts a typed
// closure to the Any form expected by the backend.
impl dyn StorageBackend {
    pub(crate) fn write_boxed<R: Send + 'static>(
        &self,
        f: WriteClosure<R>,
    ) -> BoxedFuture<'_, Result<R, StorageError>> {
        let wrapped = Box::new(
            move |c: &mut rusqlite::Connection| -> Box<dyn std::any::Any + Send> {
                Box::new(f(c))
            },
        );
        let fut = self.write_any(wrapped);
        Box::pin(async move {
            let any = fut.await?;
            any.downcast::<Result<R, StorageError>>()
                .map(|b| *b)
                .unwrap_or_else(|_| {
                    Err(StorageError::Sqlite("type mismatch in write".into()))
                })
        })
    }
}
