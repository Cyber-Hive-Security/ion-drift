//! Operator consent for the outbound vulnerability feed.
//!
//! The feed is on by default, but "default" means preselected: nothing is
//! fetched until an administrator has answered. A missing or unrecognised
//! value reads as [`FeedConsent::Unanswered`], so a corrupt setting fails
//! closed — no outbound traffic — rather than open.

use ion_drift_storage::SwitchStore;
use serde::{Deserialize, Serialize};

pub(crate) const CONSENT_KEY: &str = "advisory_feed_consent";
pub(crate) const CONSENT_BY_KEY: &str = "advisory_feed_consent_by";
pub(crate) const CONSENT_AT_KEY: &str = "advisory_feed_consent_at";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FeedConsent {
    Unanswered,
    On,
    Off,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ConsentRecord {
    pub consent: FeedConsent,
    pub set_by: Option<String>,
    pub set_at: Option<i64>,
}

pub(crate) async fn load(store: &SwitchStore) -> Result<ConsentRecord, String> {
    let raw = store
        .get_setting(CONSENT_KEY)
        .await
        .map_err(|e| format!("read feed consent: {e}"))?;
    let consent = match raw.as_deref() {
        Some("on") => FeedConsent::On,
        Some("off") => FeedConsent::Off,
        _ => FeedConsent::Unanswered,
    };
    if consent == FeedConsent::Unanswered {
        return Ok(ConsentRecord { consent, set_by: None, set_at: None });
    }
    let set_by = store
        .get_setting(CONSENT_BY_KEY)
        .await
        .map_err(|e| format!("read feed consent author: {e}"))?;
    let set_at = store
        .get_setting(CONSENT_AT_KEY)
        .await
        .map_err(|e| format!("read feed consent time: {e}"))?
        .and_then(|s| s.parse().ok());
    Ok(ConsentRecord { consent, set_by, set_at })
}

/// Record an administrator's answer. `Unanswered` is not an answer.
///
/// Attribution is written before the decision, so an interrupted save leaves
/// the previous decision in force rather than a decision with no author.
pub(crate) async fn save(
    store: &SwitchStore,
    choice: FeedConsent,
    by: &str,
    now: i64,
) -> Result<(), String> {
    let value = match choice {
        FeedConsent::On => "on",
        FeedConsent::Off => "off",
        FeedConsent::Unanswered => return Err("feed consent must be on or off".to_string()),
    };
    store
        .set_setting(CONSENT_BY_KEY, by)
        .await
        .map_err(|e| format!("write feed consent author: {e}"))?;
    store
        .set_setting(CONSENT_AT_KEY, &now.to_string())
        .await
        .map_err(|e| format!("write feed consent time: {e}"))?;
    store
        .set_setting(CONSENT_KEY, value)
        .await
        .map_err(|e| format!("write feed consent: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::SwitchStore;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn fresh_install_is_unanswered() {
        let f = NamedTempFile::new().unwrap();
        let store = SwitchStore::new(f.path()).unwrap();
        let rec = load(&store).await.unwrap();
        assert_eq!(rec, ConsentRecord { consent: FeedConsent::Unanswered, set_by: None, set_at: None });
    }

    #[tokio::test]
    async fn saved_answer_persists_with_attribution_across_reopen() {
        let f = NamedTempFile::new().unwrap();
        {
            let store = SwitchStore::new(f.path()).unwrap();
            save(&store, FeedConsent::On, "scott", 1_758_700_000).await.unwrap();
        }
        let store = SwitchStore::new(f.path()).unwrap();
        let rec = load(&store).await.unwrap();
        assert_eq!(rec.consent, FeedConsent::On);
        assert_eq!(rec.set_by.as_deref(), Some("scott"));
        assert_eq!(rec.set_at, Some(1_758_700_000));
    }

    #[tokio::test]
    async fn unanswered_is_not_an_answer() {
        let f = NamedTempFile::new().unwrap();
        let store = SwitchStore::new(f.path()).unwrap();
        assert!(save(&store, FeedConsent::Unanswered, "scott", 1).await.is_err());
    }

    #[tokio::test]
    async fn corrupt_value_fails_closed() {
        let f = NamedTempFile::new().unwrap();
        let store = SwitchStore::new(f.path()).unwrap();
        store.set_setting(CONSENT_KEY, "maybe").await.unwrap();
        assert_eq!(load(&store).await.unwrap().consent, FeedConsent::Unanswered);
    }
}
