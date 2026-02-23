use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rusqlite::params;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sha2::Sha256;
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

/// Manages encryption/decryption of secrets using a key derived from a TLS private key.
pub struct SecretsManager {
    db: Arc<Mutex<rusqlite::Connection>>,
    derived_key: Key<Aes256Gcm>,
    key_fingerprint: String,
    previous_key: Option<Key<Aes256Gcm>>,
    previous_fingerprint: Option<String>,
}

impl SecretsManager {
    /// Initialize with a single TLS key file.
    pub fn new(db_path: &Path, key_path: &str) -> anyhow::Result<Self> {
        let derived_key = derive_key_from_pem(key_path)?;
        let key_fingerprint = compute_fingerprint(&derived_key);
        let db = open_db(db_path)?;

        tracing::info!(
            fingerprint = %key_fingerprint,
            "secrets manager initialized"
        );

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            derived_key,
            key_fingerprint,
            previous_key: None,
            previous_fingerprint: None,
        })
    }

    /// Initialize with current + previous TLS key for rotation support.
    pub fn new_with_previous(
        db_path: &Path,
        key_path: &str,
        previous_key_path: &str,
    ) -> anyhow::Result<Self> {
        let derived_key = derive_key_from_pem(key_path)?;
        let key_fingerprint = compute_fingerprint(&derived_key);
        let previous_key = derive_key_from_pem(previous_key_path)?;
        let previous_fingerprint = compute_fingerprint(&previous_key);
        let db = open_db(db_path)?;

        tracing::info!(
            fingerprint = %key_fingerprint,
            previous_fingerprint = %previous_fingerprint,
            "secrets manager initialized with key rotation support"
        );

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            derived_key,
            key_fingerprint,
            previous_key: Some(previous_key),
            previous_fingerprint: Some(previous_fingerprint),
        })
    }

    /// Encrypt and store a secret.
    pub async fn encrypt_secret(&self, name: &str, plaintext: &str) -> anyhow::Result<()> {
        let cipher = Aes256Gcm::new(&self.derived_key);
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
    /// If the stored fingerprint doesn't match the current key but matches the previous key,
    /// decrypts with the previous key and re-encrypts with the current key.
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

        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: &ciphertext,
            aad: name.as_bytes(),
        };

        // Try current key first
        if stored_fp == self.key_fingerprint {
            let cipher = Aes256Gcm::new(&self.derived_key);
            let plaintext = cipher
                .decrypt(nonce, payload)
                .map_err(|e| anyhow::anyhow!("decryption failed for '{name}': {e}"))?;
            let secret = String::from_utf8(plaintext)
                .map_err(|e| anyhow::anyhow!("decrypted value is not valid UTF-8: {e}"))?;
            return Ok(Some(SecretString::from(secret)));
        }

        // Try previous key for rotation
        if let (Some(prev_key), Some(prev_fp)) =
            (&self.previous_key, &self.previous_fingerprint)
        {
            if stored_fp == *prev_fp {
                let cipher = Aes256Gcm::new(prev_key);
                let payload = Payload {
                    msg: &ciphertext,
                    aad: name.as_bytes(),
                };
                let plaintext = cipher
                    .decrypt(nonce, payload)
                    .map_err(|e| anyhow::anyhow!("decryption with previous key failed for '{name}': {e}"))?;
                let secret = String::from_utf8(plaintext)
                    .map_err(|e| anyhow::anyhow!("decrypted value is not valid UTF-8: {e}"))?;

                // Re-encrypt with current key
                tracing::info!(secret = name, "re-encrypting secret with new key");
                self.encrypt_secret(name, &secret).await?;

                return Ok(Some(SecretString::from(secret)));
            }
        }

        Err(anyhow::anyhow!(
            "secret '{name}' encrypted with unknown key (fingerprint: {stored_fp})"
        ))
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

        let cipher = Aes256Gcm::new(&self.derived_key);
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

    /// Re-derive key from a new key file and re-encrypt all secrets.
    /// Returns the new fingerprint.
    pub async fn rotate_key(&mut self, new_key_path: &str) -> anyhow::Result<String> {
        let old_key = self.derived_key;
        let old_fingerprint = self.key_fingerprint.clone();
        let new_key = derive_key_from_pem(new_key_path)?;
        let new_fingerprint = compute_fingerprint(&new_key);

        if new_fingerprint == old_fingerprint {
            return Ok(new_fingerprint);
        }

        // Load all secret names and their encrypted data
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT name, ciphertext, nonce, key_fingerprint FROM encrypted_secrets",
        )?;
        let rows: Vec<(String, Vec<u8>, Vec<u8>, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        drop(stmt);

        let old_cipher = Aes256Gcm::new(&old_key);
        let new_cipher = Aes256Gcm::new(&new_key);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        db.execute_batch("BEGIN TRANSACTION")?;
        for (name, ciphertext, nonce_bytes, stored_fp) in &rows {
            if *stored_fp != old_fingerprint {
                tracing::warn!(
                    secret = %name,
                    stored_fp = %stored_fp,
                    "skipping secret with unknown fingerprint during rotation"
                );
                continue;
            }

            let nonce = Nonce::from_slice(nonce_bytes);
            let payload = Payload {
                msg: ciphertext.as_slice(),
                aad: name.as_bytes(),
            };
            let plaintext = old_cipher
                .decrypt(nonce, payload)
                .map_err(|e| anyhow::anyhow!("decryption failed for '{name}' during rotation: {e}"))?;

            let new_nonce_bytes: [u8; 12] = rand::random();
            let new_nonce = Nonce::from_slice(&new_nonce_bytes);
            let new_payload = Payload {
                msg: &plaintext,
                aad: name.as_bytes(),
            };
            let new_ciphertext = new_cipher
                .encrypt(new_nonce, new_payload)
                .map_err(|e| anyhow::anyhow!("re-encryption failed for '{name}': {e}"))?;

            db.execute(
                "UPDATE encrypted_secrets SET ciphertext = ?1, nonce = ?2, key_fingerprint = ?3, updated_at = ?4 WHERE name = ?5",
                params![new_ciphertext, new_nonce_bytes.as_slice(), new_fingerprint, now, name],
            )?;
        }
        db.execute_batch("COMMIT")?;
        drop(db);

        self.previous_key = Some(old_key);
        self.previous_fingerprint = Some(old_fingerprint);
        self.derived_key = new_key;
        self.key_fingerprint = new_fingerprint.clone();

        tracing::info!(
            new_fingerprint = %new_fingerprint,
            secrets_rotated = rows.len(),
            "TLS key rotated, secrets re-encrypted"
        );

        Ok(new_fingerprint)
    }
}

/// Derive a 32-byte AES-256 key from a PEM-encoded private key file using HKDF-SHA256.
fn derive_key_from_pem(key_path: &str) -> anyhow::Result<Key<Aes256Gcm>> {
    let pem_data = std::fs::read_to_string(key_path)
        .map_err(|e| anyhow::anyhow!("failed to read TLS key file {key_path}: {e}"))?;

    let parsed = pem::parse(&pem_data)
        .map_err(|e| anyhow::anyhow!("failed to parse PEM from {key_path}: {e}"))?;

    let ikm = parsed.contents();
    if ikm.is_empty() {
        return Err(anyhow::anyhow!("TLS key file {key_path} contains no key data"));
    }

    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(b"iondrift-secrets-v1", &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expansion failed: {e}"))?;

    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
}

/// Compute a fingerprint: first 8 bytes of SHA-256(key) as hex (16 chars).
fn compute_fingerprint(key: &Key<Aes256Gcm>) -> String {
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
