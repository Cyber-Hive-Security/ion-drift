use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rusqlite::params;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use tokio::sync::Mutex;

// Secret name constants
pub const SECRET_ROUTER_USERNAME: &str = "router_username";
pub const SECRET_ROUTER_PASSWORD: &str = "router_password";
pub const SECRET_OIDC_CLIENT_SECRET: &str = "oidc_client_secret";
pub const SECRET_SESSION_SECRET: &str = "session_secret";

/// All decrypted secrets needed by the application.
pub struct DecryptedSecrets {
    pub router_username: String,
    pub router_password: SecretString,
    pub oidc_client_secret: SecretString,
    pub session_secret: SecretString,
}

/// Status of a single stored secret.
#[derive(Debug, Clone, Serialize)]
pub struct SecretStatus {
    pub name: String,
    pub updated_at: i64,
    pub key_current: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub auto_generated: bool,
}

/// Manages encryption/decryption of secrets using a KEK retrieved from Keycloak.
pub struct SecretsManager {
    db: Arc<Mutex<rusqlite::Connection>>,
    kek: Key<Aes256Gcm>,
    key_fingerprint: String,
}

impl SecretsManager {
    /// Initialize with a raw 32-byte KEK (retrieved from Keycloak mTLS bootstrap).
    pub fn new(db_path: &Path, kek: Key<Aes256Gcm>) -> anyhow::Result<Self> {
        let key_fingerprint = compute_fingerprint(&kek);
        let db = open_db(db_path)?;

        tracing::info!(
            fingerprint = %key_fingerprint,
            "secrets manager initialized"
        );

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            kek,
            key_fingerprint,
        })
    }

    /// Encrypt and store a secret.
    pub async fn encrypt_secret(&self, name: &str, plaintext: &str) -> anyhow::Result<()> {
        let cipher = Aes256Gcm::new(&self.kek);
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Use the secret name as AAD (additional authenticated data)
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: name.as_bytes(),
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let db = self.db.lock().await;
        db.execute(
            "INSERT OR REPLACE INTO encrypted_secrets (name, ciphertext, nonce, key_fingerprint, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, ciphertext, nonce_bytes.as_slice(), self.key_fingerprint, now],
        )?;

        Ok(())
    }

    /// Decrypt a secret by name. Returns None if not found.
    pub async fn decrypt_secret(&self, name: &str) -> anyhow::Result<Option<SecretString>> {
        let (ciphertext, nonce_bytes, stored_fp) = {
            let db = self.db.lock().await;
            let mut stmt = db.prepare(
                "SELECT ciphertext, nonce, key_fingerprint FROM encrypted_secrets WHERE name = ?1",
            )?;

            let row = stmt.query_row(params![name], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            });

            match row {
                Ok(r) => r,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }; // db lock released here

        if stored_fp != self.key_fingerprint {
            return Err(anyhow::anyhow!(
                "secret '{name}' encrypted with unknown key (fingerprint: {stored_fp}, current: {})",
                self.key_fingerprint
            ));
        }

        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: &ciphertext,
            aad: name.as_bytes(),
        };

        let cipher = Aes256Gcm::new(&self.kek);
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("decryption failed for '{name}': {e}"))?;
        let secret = String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("decrypted value is not valid UTF-8: {e}"))?;

        Ok(Some(SecretString::from(secret)))
    }

    /// Check if any secrets exist in the database.
    pub async fn has_secrets(&self) -> anyhow::Result<bool> {
        let db = self.db.lock().await;
        let count: i64 =
            db.query_row("SELECT COUNT(*) FROM encrypted_secrets", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// Get status of all stored secrets.
    pub async fn secret_status(&self) -> anyhow::Result<Vec<SecretStatus>> {
        let db = self.db.lock().await;
        let mut stmt =
            db.prepare("SELECT name, updated_at, key_fingerprint FROM encrypted_secrets ORDER BY name")?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let fp = &self.key_fingerprint;
        let mut statuses = Vec::new();
        for row in rows {
            let (name, updated_at, stored_fp) = row?;
            let auto_generated = name == SECRET_SESSION_SECRET;
            statuses.push(SecretStatus {
                name,
                updated_at,
                key_current: stored_fp == *fp,
                auto_generated,
            });
        }

        Ok(statuses)
    }

    /// Store all secrets atomically in a single transaction.
    pub async fn store_all(&self, secrets: &DecryptedSecrets) -> anyhow::Result<()> {
        // Encrypt all values first
        let pairs = [
            (SECRET_ROUTER_USERNAME, secrets.router_username.as_str()),
            (SECRET_ROUTER_PASSWORD, secrets.router_password.expose_secret()),
            (SECRET_OIDC_CLIENT_SECRET, secrets.oidc_client_secret.expose_secret()),
            (SECRET_SESSION_SECRET, secrets.session_secret.expose_secret()),
        ];

        let cipher = Aes256Gcm::new(&self.kek);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut encrypted: Vec<(&str, Vec<u8>, [u8; 12])> = Vec::new();
        for (name, plaintext) in &pairs {
            let nonce_bytes: [u8; 12] = rand::random();
            let nonce = Nonce::from_slice(&nonce_bytes);
            let payload = Payload {
                msg: plaintext.as_bytes(),
                aad: name.as_bytes(),
            };
            let ciphertext = cipher
                .encrypt(nonce, payload)
                .map_err(|e| anyhow::anyhow!("encryption failed for '{name}': {e}"))?;
            encrypted.push((name, ciphertext, nonce_bytes));
        }

        // Store in a single transaction
        let db = self.db.lock().await;
        db.execute_batch("BEGIN TRANSACTION")?;
        for (name, ciphertext, nonce_bytes) in &encrypted {
            db.execute(
                "INSERT OR REPLACE INTO encrypted_secrets (name, ciphertext, nonce, key_fingerprint, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![name, ciphertext, nonce_bytes.as_slice(), self.key_fingerprint, now],
            )?;
        }
        db.execute_batch("COMMIT")?;

        tracing::info!(
            fingerprint = %self.key_fingerprint,
            "stored {} encrypted secrets",
            encrypted.len()
        );

        Ok(())
    }

    /// Load and decrypt all secrets. Returns None if any are missing.
    pub async fn load_all(&self) -> anyhow::Result<Option<DecryptedSecrets>> {
        let username = match self.decrypt_secret(SECRET_ROUTER_USERNAME).await? {
            Some(s) => s.expose_secret().to_string(),
            None => return Ok(None),
        };
        let password = match self.decrypt_secret(SECRET_ROUTER_PASSWORD).await? {
            Some(s) => s,
            None => return Ok(None),
        };
        let oidc_secret = match self.decrypt_secret(SECRET_OIDC_CLIENT_SECRET).await? {
            Some(s) => s,
            None => return Ok(None),
        };
        let session_secret = match self.decrypt_secret(SECRET_SESSION_SECRET).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        Ok(Some(DecryptedSecrets {
            router_username: username,
            router_password: password,
            oidc_client_secret: oidc_secret,
            session_secret,
        }))
    }

    /// Delete a single secret.
    pub async fn delete_secret(&self, name: &str) -> anyhow::Result<()> {
        let db = self.db.lock().await;
        db.execute("DELETE FROM encrypted_secrets WHERE name = ?1", params![name])?;
        Ok(())
    }

    /// Get the current key fingerprint.
    pub fn fingerprint(&self) -> &str {
        &self.key_fingerprint
    }
}

/// Compute a fingerprint: first 8 bytes of SHA-256(key) as hex (16 chars).
pub fn compute_fingerprint(key: &Key<Aes256Gcm>) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(key.as_slice());
    hex::encode(&hash[..8])
}

/// Open (or create) the secrets SQLite database.
fn open_db(db_path: &Path) -> anyhow::Result<rusqlite::Connection> {
    let db = rusqlite::Connection::open(db_path)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS encrypted_secrets (
            name TEXT PRIMARY KEY,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            key_fingerprint TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )",
    )?;
    // Enable WAL mode for better concurrent access
    db.execute_batch("PRAGMA journal_mode=WAL")?;
    Ok(db)
}
