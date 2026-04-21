//! SQLite-backed storage for registered modules.
//!
//! Opens its own connection to the same `secrets.db` file owned by
//! [`crate::secrets::SecretsManager`]. WAL mode (set by `SecretsManager`)
//! permits concurrent access from both connections. The `CREATE TABLE IF
//! NOT EXISTS` on construction is idempotent: whichever store opens the
//! file second simply sees the existing schema.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ion_drift_module_api::Manifest;
use rusqlite::{params, Connection, OptionalExtension};
use secrecy::SecretString;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::secrets::compute_fingerprint;

/// A module registered with Drift.
///
/// Secrets (shared HMAC key, bearer token) are NOT returned in this
/// struct. Use [`ModuleRegistryStore::get_shared_secret`] or
/// [`ModuleRegistryStore::get_api_token`] to fetch them at the point of
/// use.
#[derive(Debug, Clone, Serialize)]
pub struct RegisteredModule {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub manifest: Manifest,
    pub last_seen_at: Option<i64>,
    pub registered_at: i64,
    pub updated_at: i64,
}

/// Fields required to register a new module.
pub struct NewModuleRegistration<'a> {
    pub name: &'a str,
    pub url: &'a str,
    pub manifest: &'a Manifest,
    /// HMAC-SHA256 shared secret used to sign outbound event deliveries.
    pub shared_secret: &'a str,
    /// Bearer token Drift sends on reverse-proxied admin requests.
    pub api_token: &'a str,
}

/// Store for `registered_modules`.
pub struct ModuleRegistryStore {
    db: Arc<Mutex<Connection>>,
    kek: Key<Aes256Gcm>,
    key_fingerprint: String,
}

impl ModuleRegistryStore {
    /// Open the store, creating the table if needed.
    pub fn new(db_path: &Path, kek: Key<Aes256Gcm>) -> anyhow::Result<Self> {
        let key_fingerprint = compute_fingerprint(&kek);
        let db = Connection::open(db_path)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS registered_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                url TEXT NOT NULL,
                shared_secret_ciphertext BLOB NOT NULL,
                shared_secret_nonce BLOB NOT NULL,
                api_token_ciphertext BLOB NOT NULL,
                api_token_nonce BLOB NOT NULL,
                key_fingerprint TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                manifest_json TEXT NOT NULL,
                last_seen_at INTEGER,
                registered_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_registered_modules_enabled
                ON registered_modules(enabled);",
        )?;

        tracing::info!(
            fingerprint = %key_fingerprint,
            "module registry store initialized"
        );

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            kek,
            key_fingerprint,
        })
    }

    fn encrypt(&self, aad: &str, plaintext: &str) -> anyhow::Result<(Vec<u8>, [u8; 12])> {
        use rand::rngs::OsRng;
        use rand::TryRngCore;
        let cipher = Aes256Gcm::new(&self.kek);
        let mut nonce_bytes = [0u8; 12];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: aad.as_bytes(),
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("module secret encrypt: {e}"))?;
        Ok((ciphertext, nonce_bytes))
    }

    fn decrypt(
        &self,
        aad: &str,
        ciphertext: &[u8],
        nonce_bytes: &[u8],
    ) -> anyhow::Result<SecretString> {
        let cipher = Aes256Gcm::new(&self.kek);
        let nonce = Nonce::from_slice(nonce_bytes);
        let payload = Payload {
            msg: ciphertext,
            aad: aad.as_bytes(),
        };
        let plain = cipher
            .decrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("module secret decrypt: {e}"))?;
        let s = String::from_utf8(plain)
            .map_err(|e| anyhow::anyhow!("module secret utf8: {e}"))?;
        Ok(SecretString::from(s))
    }

    /// Insert a new module. Errors if `name` already exists.
    pub async fn register(&self, new: NewModuleRegistration<'_>) -> anyhow::Result<i64> {
        let manifest_json = serde_json::to_string(new.manifest)?;
        let aad_secret = format!("module:{}:shared_secret", new.name);
        let aad_token = format!("module:{}:api_token", new.name);
        let (ss_ct, ss_nonce) = self.encrypt(&aad_secret, new.shared_secret)?;
        let (tok_ct, tok_nonce) = self.encrypt(&aad_token, new.api_token)?;
        let now = now_unix();

        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO registered_modules (
                name, url,
                shared_secret_ciphertext, shared_secret_nonce,
                api_token_ciphertext, api_token_nonce,
                key_fingerprint, enabled, manifest_json,
                last_seen_at, registered_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, NULL, ?9, ?9)",
            params![
                new.name,
                new.url,
                ss_ct,
                ss_nonce.as_slice(),
                tok_ct,
                tok_nonce.as_slice(),
                self.key_fingerprint,
                manifest_json,
                now
            ],
        )?;
        Ok(db.last_insert_rowid())
    }

    /// Remove a module by name. Returns true if a row was deleted.
    pub async fn unregister(&self, name: &str) -> anyhow::Result<bool> {
        let db = self.db.lock().await;
        let n = db.execute(
            "DELETE FROM registered_modules WHERE name = ?1",
            params![name],
        )?;
        Ok(n > 0)
    }

    /// Enable or disable a module. Returns true if a row changed.
    pub async fn set_enabled(&self, name: &str, enabled: bool) -> anyhow::Result<bool> {
        let db = self.db.lock().await;
        let n = db.execute(
            "UPDATE registered_modules SET enabled = ?1, updated_at = ?2 WHERE name = ?3",
            params![enabled as i64, now_unix(), name],
        )?;
        Ok(n > 0)
    }

    /// Replace a module's cached manifest. Returns true if a row changed.
    pub async fn update_manifest(&self, name: &str, manifest: &Manifest) -> anyhow::Result<bool> {
        let manifest_json = serde_json::to_string(manifest)?;
        let db = self.db.lock().await;
        let n = db.execute(
            "UPDATE registered_modules SET manifest_json = ?1, updated_at = ?2 WHERE name = ?3",
            params![manifest_json, now_unix(), name],
        )?;
        Ok(n > 0)
    }

    /// Update `last_seen_at` to the current time. No-op if not found.
    pub async fn touch_last_seen(&self, name: &str) -> anyhow::Result<()> {
        let db = self.db.lock().await;
        db.execute(
            "UPDATE registered_modules SET last_seen_at = ?1 WHERE name = ?2",
            params![now_unix(), name],
        )?;
        Ok(())
    }

    /// List all registered modules.
    pub async fn list(&self) -> anyhow::Result<Vec<RegisteredModule>> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT id, name, url, enabled, manifest_json, last_seen_at, registered_at, updated_at
             FROM registered_modules ORDER BY registered_at",
        )?;
        let rows = stmt.query_map([], row_to_registered)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Fetch a single registered module by name.
    pub async fn get_by_name(&self, name: &str) -> anyhow::Result<Option<RegisteredModule>> {
        let db = self.db.lock().await;
        db.query_row(
            "SELECT id, name, url, enabled, manifest_json, last_seen_at, registered_at, updated_at
             FROM registered_modules WHERE name = ?1",
            params![name],
            row_to_registered,
        )
        .optional()
        .map_err(Into::into)
    }

    /// Decrypt the shared HMAC secret for a module. `None` if the module
    /// isn't registered.
    pub async fn get_shared_secret(&self, name: &str) -> anyhow::Result<Option<SecretString>> {
        let (ciphertext, nonce) = {
            let db = self.db.lock().await;
            db.query_row(
                "SELECT shared_secret_ciphertext, shared_secret_nonce FROM registered_modules
                 WHERE name = ?1",
                params![name],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(c, n)| (c, n))
        }
        .map(|x| x)
        .unwrap_or((Vec::new(), Vec::new()));
        if ciphertext.is_empty() {
            return Ok(None);
        }
        let aad = format!("module:{}:shared_secret", name);
        Ok(Some(self.decrypt(&aad, &ciphertext, &nonce)?))
    }

    /// Decrypt the bearer token Drift uses when reverse-proxying admin
    /// requests to this module. `None` if the module isn't registered.
    pub async fn get_api_token(&self, name: &str) -> anyhow::Result<Option<SecretString>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = {
            let db = self.db.lock().await;
            db.query_row(
                "SELECT api_token_ciphertext, api_token_nonce FROM registered_modules
                 WHERE name = ?1",
                params![name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
        };
        let Some((ciphertext, nonce)) = row else {
            return Ok(None);
        };
        let aad = format!("module:{}:api_token", name);
        Ok(Some(self.decrypt(&aad, &ciphertext, &nonce)?))
    }
}

fn row_to_registered(row: &rusqlite::Row<'_>) -> rusqlite::Result<RegisteredModule> {
    let manifest_json: String = row.get(4)?;
    let manifest = serde_json::from_str::<Manifest>(&manifest_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(RegisteredModule {
        id: row.get(0)?,
        name: row.get(1)?,
        url: row.get(2)?,
        enabled: row.get::<_, i64>(3)? != 0,
        manifest,
        last_seen_at: row.get(5)?,
        registered_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_module_api::{ApiVersion, EventKind, ProtocolVariant, RouteDescriptor};
    use secrecy::ExposeSecret;
    use tempfile::NamedTempFile;

    fn test_kek() -> Key<Aes256Gcm> {
        let bytes: [u8; 32] = [7u8; 32];
        Key::<Aes256Gcm>::from_slice(&bytes).to_owned()
    }

    fn sample_manifest(name: &str) -> Manifest {
        Manifest {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            api_version: ApiVersion::CURRENT,
            protocol: ProtocolVariant::Http,
            description: Some("test".into()),
            subscribed_events: vec![EventKind::AnomalyDetected],
            exposed_routes: vec![RouteDescriptor {
                path: "/watchlist".into(),
                method: "GET".into(),
                description: None,
            }],
        }
    }

    #[tokio::test]
    async fn register_and_list() {
        let tmp = NamedTempFile::new().unwrap();
        let store = ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap();

        let m = sample_manifest("scout-shield");
        let id = store
            .register(NewModuleRegistration {
                name: "scout-shield",
                url: "http://127.0.0.1:3099",
                manifest: &m,
                shared_secret: "s-secret",
                api_token: "bearer-abc",
            })
            .await
            .unwrap();
        assert!(id > 0);

        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "scout-shield");
        assert!(all[0].enabled);
        assert_eq!(all[0].manifest.subscribed_events, vec![EventKind::AnomalyDetected]);
    }

    #[tokio::test]
    async fn secrets_round_trip() {
        let tmp = NamedTempFile::new().unwrap();
        let store = ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap();
        let m = sample_manifest("scout-shield");
        store
            .register(NewModuleRegistration {
                name: "scout-shield",
                url: "http://x",
                manifest: &m,
                shared_secret: "my-hmac-key",
                api_token: "my-bearer",
            })
            .await
            .unwrap();

        let ss = store.get_shared_secret("scout-shield").await.unwrap().unwrap();
        assert_eq!(ss.expose_secret(), "my-hmac-key");
        let tok = store.get_api_token("scout-shield").await.unwrap().unwrap();
        assert_eq!(tok.expose_secret(), "my-bearer");

        assert!(store.get_shared_secret("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn enable_disable_and_touch() {
        let tmp = NamedTempFile::new().unwrap();
        let store = ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap();
        store
            .register(NewModuleRegistration {
                name: "m",
                url: "http://x",
                manifest: &sample_manifest("m"),
                shared_secret: "a",
                api_token: "b",
            })
            .await
            .unwrap();

        assert!(store.set_enabled("m", false).await.unwrap());
        let got = store.get_by_name("m").await.unwrap().unwrap();
        assert!(!got.enabled);

        store.touch_last_seen("m").await.unwrap();
        let got = store.get_by_name("m").await.unwrap().unwrap();
        assert!(got.last_seen_at.is_some());
    }

    #[tokio::test]
    async fn unique_name_constraint() {
        let tmp = NamedTempFile::new().unwrap();
        let store = ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap();
        let m = sample_manifest("dup");
        store
            .register(NewModuleRegistration {
                name: "dup",
                url: "http://x",
                manifest: &m,
                shared_secret: "a",
                api_token: "b",
            })
            .await
            .unwrap();
        let second = store
            .register(NewModuleRegistration {
                name: "dup",
                url: "http://y",
                manifest: &m,
                shared_secret: "a",
                api_token: "b",
            })
            .await;
        assert!(second.is_err());
    }

    #[tokio::test]
    async fn unregister_removes_row() {
        let tmp = NamedTempFile::new().unwrap();
        let store = ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap();
        store
            .register(NewModuleRegistration {
                name: "m",
                url: "http://x",
                manifest: &sample_manifest("m"),
                shared_secret: "a",
                api_token: "b",
            })
            .await
            .unwrap();
        assert!(store.unregister("m").await.unwrap());
        assert!(store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_manifest_persists() {
        let tmp = NamedTempFile::new().unwrap();
        let store = ModuleRegistryStore::new(tmp.path(), test_kek()).unwrap();
        let m = sample_manifest("m");
        store
            .register(NewModuleRegistration {
                name: "m",
                url: "http://x",
                manifest: &m,
                shared_secret: "a",
                api_token: "b",
            })
            .await
            .unwrap();
        let mut m2 = m.clone();
        m2.version = "0.2.0".into();
        assert!(store.update_manifest("m", &m2).await.unwrap());
        let got = store.get_by_name("m").await.unwrap().unwrap();
        assert_eq!(got.manifest.version, "0.2.0");
    }
}
