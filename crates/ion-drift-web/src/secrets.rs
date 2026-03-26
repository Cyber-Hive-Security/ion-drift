use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rusqlite::{params, OptionalExtension};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// Secret name constants
pub const SECRET_ROUTER_USERNAME: &str = "router_username";
pub const SECRET_ROUTER_PASSWORD: &str = "router_password";
pub const SECRET_OIDC_CLIENT_SECRET: &str = "oidc_client_secret";
pub const SECRET_SESSION_SECRET: &str = "session_secret";
pub const SECRET_CW_CERT_API_KEY: &str = "certwarden_cert_api_key";
pub const SECRET_CW_KEY_API_KEY: &str = "certwarden_key_api_key";
pub const SECRET_MAXMIND_ACCOUNT_ID: &str = "maxmind_account_id";
pub const SECRET_MAXMIND_LICENSE_KEY: &str = "maxmind_license_key";

/// All decrypted secrets needed by the application.
pub struct DecryptedSecrets {
    pub router_username: String,
    pub router_password: SecretString,
    pub oidc_client_secret: SecretString,
    pub session_secret: SecretString,
    /// CertWarden certificate API key (optional — not present in legacy setups).
    pub certwarden_cert_api_key: Option<SecretString>,
    /// CertWarden private key API key (optional — not present in legacy setups).
    pub certwarden_key_api_key: Option<SecretString>,
    /// MaxMind GeoLite2 account ID (optional — for auto-download).
    pub maxmind_account_id: Option<SecretString>,
    /// MaxMind GeoLite2 license key (optional — for auto-download).
    pub maxmind_license_key: Option<SecretString>,
}

/// All known secret names (used to populate the settings UI).
pub const ALL_SECRET_NAMES: &[&str] = &[
    SECRET_ROUTER_USERNAME,
    SECRET_ROUTER_PASSWORD,
    SECRET_OIDC_CLIENT_SECRET,
    SECRET_SESSION_SECRET,
    SECRET_CW_CERT_API_KEY,
    SECRET_CW_KEY_API_KEY,
    SECRET_MAXMIND_ACCOUNT_ID,
    SECRET_MAXMIND_LICENSE_KEY,
];

/// Status of a single stored secret.
#[derive(Debug, Clone, Serialize)]
pub struct SecretStatus {
    pub name: String,
    pub updated_at: i64,
    pub key_current: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub auto_generated: bool,
    /// Whether this secret has been stored (false = not yet configured).
    pub stored: bool,
}

/// A local user account.
#[derive(Debug, Clone, Serialize)]
pub struct LocalUser {
    pub username: String,
    pub role: String,
    pub created_at: i64,
}

/// A device registered in the device registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub ca_cert_path: Option<String>,
    pub device_type: String,
    pub model: Option<String>,
    pub is_primary: bool,
    pub enabled: bool,
    pub poll_interval_secs: u32,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Data for creating a new device.
#[derive(Debug, Clone, Deserialize)]
pub struct NewDevice {
    pub id: String,
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_tls")]
    pub tls: bool,
    pub ca_cert_path: Option<String>,
    pub device_type: String,
    pub model: Option<String>,
    #[serde(default)]
    pub is_primary: bool,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u32,
}

fn default_port() -> u16 { 443 }
fn default_tls() -> bool { true }
fn default_enabled() -> bool { true }
fn default_poll_interval() -> u32 { 60 }

/// Data for updating an existing device (all fields optional).
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateDevice {
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tls: Option<bool>,
    pub ca_cert_path: Option<String>,
    pub model: Option<String>,
    pub enabled: Option<bool>,
    pub poll_interval_secs: Option<u32>,
    pub username: Option<String>,
    pub password: Option<String>,
    // SNMPv3 extras
    pub snmp_auth_protocol: Option<String>,
    pub snmp_priv_password: Option<String>,
    pub snmp_priv_protocol: Option<String>,
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

    /// Encrypt a value with the KEK, using the secret name as AAD.
    /// Returns (ciphertext, nonce_bytes).
    fn encrypt_value(&self, name: &str, plaintext: &str) -> anyhow::Result<(Vec<u8>, [u8; 12])> {
        use rand::rngs::OsRng;
        use rand::TryRngCore;
        let cipher = Aes256Gcm::new(&self.kek);
        let mut nonce_bytes = [0u8; 12];
        OsRng.try_fill_bytes(&mut nonce_bytes).expect("OS RNG unavailable");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: name.as_bytes(),
        };
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("encryption failed for '{name}': {e}"))?;
        Ok((ciphertext, nonce_bytes))
    }

    /// Encrypt and store a secret.
    pub async fn encrypt_secret(&self, name: &str, plaintext: &str) -> anyhow::Result<()> {
        let (ciphertext, nonce_bytes) = self.encrypt_value(name, plaintext)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
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

    /// Get status of all known secrets (stored and not-yet-stored).
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
        let mut stored: std::collections::HashMap<String, (i64, bool)> =
            std::collections::HashMap::new();
        for row in rows {
            let (name, updated_at, stored_fp) = row?;
            stored.insert(name, (updated_at, stored_fp == *fp));
        }

        let mut statuses = Vec::new();
        for &name in ALL_SECRET_NAMES {
            let auto_generated = name == SECRET_SESSION_SECRET;
            if let Some(&(updated_at, key_current)) = stored.get(name) {
                statuses.push(SecretStatus {
                    name: name.to_string(),
                    updated_at,
                    key_current,
                    auto_generated,
                    stored: true,
                });
            } else {
                statuses.push(SecretStatus {
                    name: name.to_string(),
                    updated_at: 0,
                    key_current: false,
                    auto_generated,
                    stored: false,
                });
            }
        }

        Ok(statuses)
    }

    /// Store all secrets atomically in a single transaction.
    pub async fn store_all(&self, secrets: &DecryptedSecrets) -> anyhow::Result<()> {
        // Encrypt all values first — core secrets always present
        let mut pairs: Vec<(&str, &str)> = vec![
            (SECRET_ROUTER_USERNAME, secrets.router_username.as_str()),
            (SECRET_ROUTER_PASSWORD, secrets.router_password.expose_secret()),
            (SECRET_OIDC_CLIENT_SECRET, secrets.oidc_client_secret.expose_secret()),
            (SECRET_SESSION_SECRET, secrets.session_secret.expose_secret()),
        ];

        // CertWarden secrets are optional
        if let Some(ref key) = secrets.certwarden_cert_api_key {
            pairs.push((SECRET_CW_CERT_API_KEY, key.expose_secret()));
        }
        if let Some(ref key) = secrets.certwarden_key_api_key {
            pairs.push((SECRET_CW_KEY_API_KEY, key.expose_secret()));
        }
        // MaxMind secrets are optional
        if let Some(ref key) = secrets.maxmind_account_id {
            pairs.push((SECRET_MAXMIND_ACCOUNT_ID, key.expose_secret()));
        }
        if let Some(ref key) = secrets.maxmind_license_key {
            pairs.push((SECRET_MAXMIND_LICENSE_KEY, key.expose_secret()));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut encrypted: Vec<(&str, Vec<u8>, [u8; 12])> = Vec::new();
        for (name, plaintext) in &pairs {
            let (ciphertext, nonce_bytes) = self.encrypt_value(name, plaintext)?;
            encrypted.push((name, ciphertext, nonce_bytes));
        }

        // Store in a single transaction (RAII — auto-rollback on error)
        let db = self.db.lock().await;
        let tx = db.unchecked_transaction()?;
        for (name, ciphertext, nonce_bytes) in &encrypted {
            tx.execute(
                "INSERT OR REPLACE INTO encrypted_secrets (name, ciphertext, nonce, key_fingerprint, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![name, ciphertext, nonce_bytes.as_slice(), self.key_fingerprint, now],
            )?;
        }
        tx.commit()?;

        tracing::info!(
            fingerprint = %self.key_fingerprint,
            "stored {} encrypted secrets",
            encrypted.len()
        );

        Ok(())
    }

    /// Load and decrypt all secrets. Returns None if core secrets are missing.
    /// CertWarden secrets are optional and loaded as Option.
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

        // CertWarden secrets are optional (not present in legacy setups)
        let cw_cert_key = self.decrypt_secret(SECRET_CW_CERT_API_KEY).await?;
        let cw_key_key = self.decrypt_secret(SECRET_CW_KEY_API_KEY).await?;

        // MaxMind secrets are optional
        let maxmind_account = self.decrypt_secret(SECRET_MAXMIND_ACCOUNT_ID).await?;
        let maxmind_license = self.decrypt_secret(SECRET_MAXMIND_LICENSE_KEY).await?;

        Ok(Some(DecryptedSecrets {
            router_username: username,
            router_password: password,
            oidc_client_secret: oidc_secret,
            session_secret,
            certwarden_cert_api_key: cw_cert_key,
            certwarden_key_api_key: cw_key_key,
            maxmind_account_id: maxmind_account,
            maxmind_license_key: maxmind_license,
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

    // ── Device registry ─────────────────────────────────────────

    /// List all registered devices.
    pub async fn list_devices(&self) -> anyhow::Result<Vec<DeviceRecord>> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT id, name, host, port, tls, ca_cert_path, device_type, model,
                    is_primary, enabled, poll_interval_secs, created_at, updated_at
             FROM devices ORDER BY is_primary DESC, name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DeviceRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                host: row.get(2)?,
                port: row.get::<_, i64>(3)? as u16,
                tls: row.get::<_, i32>(4)? != 0,
                ca_cert_path: row.get(5)?,
                device_type: row.get(6)?,
                model: row.get(7)?,
                is_primary: row.get::<_, i32>(8)? != 0,
                enabled: row.get::<_, i32>(9)? != 0,
                poll_interval_secs: row.get::<_, i64>(10)? as u32,
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get a single device by ID.
    pub async fn get_device(&self, id: &str) -> anyhow::Result<Option<DeviceRecord>> {
        let db = self.db.lock().await;
        let result = db.query_row(
            "SELECT id, name, host, port, tls, ca_cert_path, device_type, model,
                    is_primary, enabled, poll_interval_secs, created_at, updated_at
             FROM devices WHERE id = ?1",
            params![id],
            |row| {
                Ok(DeviceRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    host: row.get(2)?,
                    port: row.get::<_, i64>(3)? as u16,
                    tls: row.get::<_, i32>(4)? != 0,
                    ca_cert_path: row.get(5)?,
                    device_type: row.get(6)?,
                    model: row.get(7)?,
                    is_primary: row.get::<_, i32>(8)? != 0,
                    enabled: row.get::<_, i32>(9)? != 0,
                    poll_interval_secs: row.get::<_, i64>(10)? as u32,
                    created_at: row.get(11)?,
                    updated_at: row.get(12)?,
                })
            },
        );
        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Add a new device to the registry and store its encrypted credentials.
    ///
    /// All writes (device row + encrypted credentials) happen in a single
    /// SQLite transaction so the operation is atomic.
    pub async fn add_device(
        &self,
        device: &NewDevice,
        username: &str,
        password: &str,
    ) -> anyhow::Result<()> {
        let now = now_unix();

        // Pre-encrypt credentials before taking the DB lock
        let user_secret_name = format!("device:{}:username", device.id);
        let pass_secret_name = format!("device:{}:password", device.id);

        let (user_ciphertext, user_nonce_bytes) = self.encrypt_value(&user_secret_name, username)?;
        let (pass_ciphertext, pass_nonce_bytes) = self.encrypt_value(&pass_secret_name, password)?;

        // Single transaction: device row + both credential secrets
        let db = self.db.lock().await;
        let tx = db.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO devices
             (id, name, host, port, tls, ca_cert_path, device_type, model,
              is_primary, enabled, poll_interval_secs, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)",
            params![
                device.id,
                device.name,
                device.host,
                device.port as i64,
                device.tls as i32,
                device.ca_cert_path,
                device.device_type,
                device.model,
                device.is_primary as i32,
                device.enabled as i32,
                device.poll_interval_secs as i64,
                now,
            ],
        )?;

        tx.execute(
            "INSERT OR REPLACE INTO encrypted_secrets (name, ciphertext, nonce, key_fingerprint, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user_secret_name, user_ciphertext, user_nonce_bytes.as_slice(), self.key_fingerprint, now],
        )?;

        tx.execute(
            "INSERT OR REPLACE INTO encrypted_secrets (name, ciphertext, nonce, key_fingerprint, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![pass_secret_name, pass_ciphertext, pass_nonce_bytes.as_slice(), self.key_fingerprint, now],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Update a device's configuration.
    pub async fn update_device(&self, id: &str, update: &UpdateDevice) -> anyhow::Result<()> {
        let now = now_unix();

        // Pre-encrypt any credential updates before taking the DB lock for the transaction
        let encrypted_username = if let Some(ref username) = update.username {
            let name = format!("device:{id}:username");
            let (ct, nonce) = self.encrypt_value(&name, username)?;
            Some((name, ct, nonce))
        } else {
            None
        };

        let encrypted_password = if let Some(ref password) = update.password {
            let name = format!("device:{id}:password");
            let (ct, nonce) = self.encrypt_value(&name, password)?;
            Some((name, ct, nonce))
        } else {
            None
        };

        let encrypted_snmp: Vec<(String, Vec<u8>, [u8; 12])> = {
            let mut v = Vec::new();
            if let Some(ref pp) = update.snmp_priv_password {
                let name = format!("device:{id}:snmp_priv_password");
                let (ct, nonce) = self.encrypt_value(&name, pp)?;
                v.push((name, ct, nonce));
            }
            if let Some(ref ap) = update.snmp_auth_protocol {
                let name = format!("device:{id}:snmp_auth_proto");
                let (ct, nonce) = self.encrypt_value(&name, ap)?;
                v.push((name, ct, nonce));
            }
            if let Some(ref pp) = update.snmp_priv_protocol {
                let name = format!("device:{id}:snmp_priv_proto");
                let (ct, nonce) = self.encrypt_value(&name, pp)?;
                v.push((name, ct, nonce));
            }
            v
        };

        // Single transaction: update device row + all credential secrets
        let db = self.db.lock().await;
        let tx = db.unchecked_transaction()?;

        let rows = tx.execute(
            "UPDATE devices SET
                name = COALESCE(?2, name),
                host = COALESCE(?3, host),
                port = COALESCE(?4, port),
                tls = COALESCE(?5, tls),
                ca_cert_path = COALESCE(?6, ca_cert_path),
                model = COALESCE(?7, model),
                enabled = COALESCE(?8, enabled),
                poll_interval_secs = COALESCE(?9, poll_interval_secs),
                updated_at = ?1
             WHERE id = ?10",
            params![
                now,
                update.name,
                update.host,
                update.port.map(|p| p as i64),
                update.tls.map(|t| t as i32),
                update.ca_cert_path.as_deref(),
                update.model.as_deref(),
                update.enabled.map(|e| e as i32),
                update.poll_interval_secs.map(|p| p as i64),
                id,
            ],
        )?;
        if rows == 0 {
            return Err(anyhow::anyhow!("device not found: {id}"));
        }

        // Store encrypted credentials within the same transaction
        let insert_sql = "INSERT OR REPLACE INTO encrypted_secrets (name, ciphertext, nonce, key_fingerprint, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)";
        if let Some((ref name, ref ct, ref nonce)) = encrypted_username {
            tx.execute(insert_sql, params![name, ct, nonce.as_slice(), self.key_fingerprint, now])?;
        }
        if let Some((ref name, ref ct, ref nonce)) = encrypted_password {
            tx.execute(insert_sql, params![name, ct, nonce.as_slice(), self.key_fingerprint, now])?;
        }
        for (name, ct, nonce) in &encrypted_snmp {
            tx.execute(insert_sql, params![name, ct, nonce.as_slice(), self.key_fingerprint, now])?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Remove a device and its credentials atomically.
    ///
    /// Device row and all associated secrets are deleted in a single
    /// transaction.  If any secret deletion fails, the entire operation
    /// is rolled back so no orphaned rows are left behind.
    pub async fn remove_device(&self, id: &str) -> anyhow::Result<()> {
        let secret_names: Vec<String> = vec![
            format!("device:{id}:username"),
            format!("device:{id}:password"),
            format!("device:{id}:snmp_priv_password"),
            format!("device:{id}:snmp_auth_proto"),
            format!("device:{id}:snmp_priv_proto"),
        ];

        let db = self.db.lock().await;
        let tx = db.unchecked_transaction()?;

        tx.execute("DELETE FROM devices WHERE id = ?1", params![id])?;
        for name in &secret_names {
            tx.execute(
                "DELETE FROM encrypted_secrets WHERE name = ?1",
                params![name],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Get decrypted credentials for a device.
    pub async fn get_device_credentials(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<(String, SecretString)>> {
        let username = self
            .decrypt_secret(&format!("device:{id}:username"))
            .await?;
        let password = self
            .decrypt_secret(&format!("device:{id}:password"))
            .await?;
        match (username, password) {
            (Some(u), Some(p)) => Ok(Some((u.expose_secret().to_string(), p))),
            _ => Ok(None),
        }
    }

    /// Store SNMPv3 extra credentials for a device.
    pub async fn store_snmp_v3_secrets(
        &self,
        device_id: &str,
        priv_password: Option<&str>,
        auth_proto: Option<&str>,
        priv_proto: Option<&str>,
    ) -> anyhow::Result<()> {
        if let Some(pp) = priv_password {
            self.encrypt_secret(&format!("device:{device_id}:snmp_priv_password"), pp)
                .await?;
        }
        if let Some(ap) = auth_proto {
            self.encrypt_secret(&format!("device:{device_id}:snmp_auth_proto"), ap)
                .await?;
        }
        if let Some(pp) = priv_proto {
            self.encrypt_secret(&format!("device:{device_id}:snmp_priv_proto"), pp)
                .await?;
        }
        Ok(())
    }

    /// Get SNMPv3 extra params: (priv_password, auth_protocol, priv_protocol).
    pub async fn get_snmp_v3_params(
        &self,
        id: &str,
    ) -> anyhow::Result<(Option<String>, Option<String>, Option<String>)> {
        let priv_pw = self
            .decrypt_secret(&format!("device:{id}:snmp_priv_password"))
            .await?;
        let auth_proto = self
            .decrypt_secret(&format!("device:{id}:snmp_auth_proto"))
            .await?;
        let priv_proto = self
            .decrypt_secret(&format!("device:{id}:snmp_priv_proto"))
            .await?;
        Ok((
            priv_pw.map(|s| s.expose_secret().to_string()),
            auth_proto.map(|s| s.expose_secret().to_string()),
            priv_proto.map(|s| s.expose_secret().to_string()),
        ))
    }

    /// Check if the devices table has any entries.
    pub async fn has_devices(&self) -> anyhow::Result<bool> {
        let db = self.db.lock().await;
        let count: i64 =
            db.query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// Check if a specific device ID exists in the registry.
    pub async fn has_device(&self, id: &str) -> anyhow::Result<bool> {
        let db = self.db.lock().await;
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM devices WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Migrate a device from one ID to another, re-encrypting all associated secrets.
    ///
    /// Required because secrets use the secret name as AAD — a simple rename would
    /// break decryption. This method decrypts with the old AAD and re-encrypts with
    /// the new AAD, all in a single transaction.
    ///
    /// Returns the number of secrets re-encrypted.
    pub async fn migrate_device_id(&self, old_id: &str, new_id: &str) -> anyhow::Result<usize> {
        // Find all secrets keyed to the old device ID
        let old_prefix = format!("device:{old_id}:");
        let new_prefix = format!("device:{new_id}:");

        let db = self.db.lock().await;

        // Collect secret names for this device
        let mut stmt = db.prepare(
            "SELECT name FROM encrypted_secrets WHERE name LIKE ?1"
        )?;
        let names: Vec<String> = stmt.query_map(
            params![format!("{old_prefix}%")],
            |row| row.get(0),
        )?.filter_map(|r| r.ok()).collect();
        drop(stmt);

        if names.is_empty() && !self.has_device_in_db(&db, old_id)? {
            return Ok(0);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let tx = db.unchecked_transaction()?;

        // Re-encrypt each secret with the new name as AAD
        let mut count = 0;
        for old_name in &names {
            let suffix = old_name.strip_prefix(&old_prefix).unwrap_or(old_name);
            let new_name = format!("{new_prefix}{suffix}");

            // Decrypt with old AAD
            let row = tx.query_row(
                "SELECT ciphertext, nonce, key_fingerprint FROM encrypted_secrets WHERE name = ?1",
                params![old_name],
                |row| Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                )),
            )?;
            let (ciphertext, nonce_bytes, stored_fp) = row;

            if stored_fp != self.key_fingerprint {
                return Err(anyhow::anyhow!(
                    "cannot migrate '{old_name}': encrypted with different key (fingerprint: {stored_fp}, current: {})",
                    self.key_fingerprint
                ));
            }

            let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
            let cipher = aes_gcm::Aes256Gcm::new(&self.kek);
            use aes_gcm::aead::{Aead, KeyInit, Payload};

            let plaintext = cipher
                .decrypt(nonce, Payload { msg: &ciphertext, aad: old_name.as_bytes() })
                .map_err(|e| anyhow::anyhow!("decrypt failed for '{old_name}': {e}"))?;

            // Re-encrypt with new AAD
            let (new_ct, new_nonce) = self.encrypt_value(&new_name, &String::from_utf8_lossy(&plaintext))?;

            // Delete old, insert new
            tx.execute("DELETE FROM encrypted_secrets WHERE name = ?1", params![old_name])?;
            tx.execute(
                "INSERT OR REPLACE INTO encrypted_secrets (name, ciphertext, nonce, key_fingerprint, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![new_name, new_ct, new_nonce.as_slice(), self.key_fingerprint, now],
            )?;
            count += 1;
        }

        // Update the device row ID
        tx.execute(
            "UPDATE devices SET id = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_id, now, old_id],
        )?;

        tx.commit()?;
        Ok(count)
    }

    /// Internal helper: check if device exists without acquiring lock (caller holds it).
    fn has_device_in_db(&self, db: &rusqlite::Connection, id: &str) -> anyhow::Result<bool> {
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM devices WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // ── Local user management ───────────────────────────────────

    /// Create a local user with argon2id-hashed password.
    pub async fn create_local_user(&self, username: &str, password: &str, role: &str) -> anyhow::Result<()> {
        use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
        use argon2::password_hash::rand_core::OsRng;

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))?
            .to_string();

        let now = now_unix();

        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO local_users (username, password_hash, role, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![username, hash, role, now, now],
        )?;
        Ok(())
    }

    /// Verify a local user's password. Returns the user's role on success.
    pub async fn verify_local_user(&self, username: &str, password: &str) -> anyhow::Result<Option<LocalUser>> {
        use argon2::{Argon2, PasswordVerifier, PasswordHash};

        let db = self.db.lock().await;
        let result: Option<(String, String, i64)> = db.query_row(
            "SELECT password_hash, role, created_at FROM local_users WHERE username = ?1",
            params![username],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;

        let Some((hash_str, role, created_at)) = result else {
            return Ok(None);
        };

        let parsed_hash = PasswordHash::new(&hash_str)
            .map_err(|e| anyhow::anyhow!("invalid stored hash: {e}"))?;

        if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok() {
            Ok(Some(LocalUser {
                username: username.to_string(),
                role,
                created_at,
            }))
        } else {
            Ok(None)
        }
    }

    /// Check if any local users exist.
    pub async fn has_local_users(&self) -> anyhow::Result<bool> {
        let db = self.db.lock().await;
        let count: i64 = db.query_row("SELECT COUNT(*) FROM local_users", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// List all local users (without password hashes).
    pub async fn list_local_users(&self) -> anyhow::Result<Vec<LocalUser>> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare("SELECT username, role, created_at FROM local_users ORDER BY created_at")?;
        let users = stmt.query_map([], |row| {
            Ok(LocalUser {
                username: row.get(0)?,
                role: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;
        Ok(users)
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
        );
        CREATE TABLE IF NOT EXISTS local_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 443,
            tls INTEGER NOT NULL DEFAULT 1,
            ca_cert_path TEXT,
            device_type TEXT NOT NULL,
            model TEXT,
            is_primary INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            poll_interval_secs INTEGER NOT NULL DEFAULT 60,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );",
    )?;
    // Enable WAL mode for better concurrent access
    db.execute_batch("PRAGMA journal_mode=WAL")?;
    Ok(db)
}

/// Current Unix timestamp in seconds.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
