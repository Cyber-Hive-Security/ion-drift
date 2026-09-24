//! Vulnerability feed — daily NVD + CISA KEV pull for RouterOS.
//!
//! Outbound traffic is gated on operator consent: while the answer is anything
//! but `on`, this task makes no request at all. Hosts are compile-time
//! constants — never configuration — and redirects are only followed within
//! the same host, so no operator-, catalog-, or module-influenced destination
//! is ever contacted.

use std::time::Duration;

use ion_drift_storage::{AdvisoryStore, FeedCve};

use crate::advisory::consent::{self, FeedConsent};
use crate::advisory::exploitation::now_unix;
use crate::advisory::feed;
use crate::state::AppState;
use crate::task_supervisor::TaskSupervisor;

pub(crate) const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub(crate) const ROUTEROS_CPE: &str = "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*";
pub(crate) const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const STARTUP_DELAY_SECS: u64 = 240;
const REFRESH_SECS: u64 = 86_400;
/// While consent is not `on`, re-read it this often, so a "Keep on" answer
/// starts the feed within minutes.
const CONSENT_RECHECK_SECS: u64 = 300;
const RETRY_SECS: u64 = 3_600;
const JITTER_SECS: u64 = 1_800;
const PAGE_SIZE: u64 = 2_000;
const MAX_PAGES: u64 = 10;
/// NVD's unauthenticated limit is 5 requests per rolling 30 s.
const PAGE_GAP: Duration = Duration::from_secs(7);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Version deliberately omitted: the disclosure promises nothing about the installation is sent.
pub(crate) const FEED_USER_AGENT: &str = "ion-drift";

pub(crate) trait FeedTransport {
    async fn get(&self, url: &str) -> Result<Vec<u8>, String>;
}

pub(crate) struct ReqwestTransport {
    client: reqwest::Client,
}

impl FeedTransport for ReqwestTransport {
    async fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        let mut resp = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .header(
                reqwest::header::USER_AGENT,
                FEED_USER_AGENT,
            )
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("read failed: {e}"))? {
            if body.len() + chunk.len() > feed::MAX_BODY_BYTES {
                return Err("response exceeded size cap".to_string());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn build_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let same_host = attempt.previous().first().and_then(|u| u.host_str())
                == attempt.url().host_str();
            if same_host && attempt.previous().len() < 3 {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|e| format!("build feed http client: {e}"))
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct FeedCycleReport {
    pub skipped_for_consent: bool,
    pub nvd: Option<Result<usize, String>>,
    pub kev: Option<Result<usize, String>>,
}

/// One feed cycle. With consent anything but `On`, returns without a request.
/// NVD and KEV are independent: one failing never blocks the other, and a
/// failure never replaces stored data.
pub(crate) async fn run_feed_cycle<T: FeedTransport>(
    consent: FeedConsent,
    transport: &T,
    store: &AdvisoryStore,
    now: i64,
    page_gap: Duration,
) -> FeedCycleReport {
    if consent != FeedConsent::On {
        return FeedCycleReport { skipped_for_consent: true, ..Default::default() };
    }

    let nvd = match fetch_nvd(transport, page_gap).await {
        Ok(cves) => store.replace_feed_cves(&cves, now).await,
        Err(e) => Err(e),
    };
    record(store, "nvd", now, &nvd).await;

    let kev = match transport.get(KEV_URL).await.and_then(|b| feed::parse_kev(&b)) {
        Ok(entries) => store.replace_feed_kev(&entries, now).await,
        Err(e) => Err(e),
    };
    record(store, "kev", now, &kev).await;

    FeedCycleReport { skipped_for_consent: false, nvd: Some(nvd), kev: Some(kev) }
}

async fn record(store: &AdvisoryStore, source: &str, now: i64, outcome: &Result<usize, String>) {
    let outcome = outcome.as_ref().map(|n| *n as i64).map_err(String::as_str);
    if let Err(e) = store.record_feed_attempt(source, now, outcome).await {
        tracing::warn!(source, error = %e, "advisory feed: could not record attempt");
    }
}

async fn fetch_nvd<T: FeedTransport>(transport: &T, page_gap: Duration) -> Result<Vec<FeedCve>, String> {
    let mut all: Vec<FeedCve> = Vec::new();
    let mut start = 0u64;
    for page_no in 0..MAX_PAGES {
        if page_no > 0 {
            tokio::time::sleep(page_gap).await;
        }
        let url = format!(
            "{NVD_URL}?virtualMatchString={ROUTEROS_CPE}&resultsPerPage={PAGE_SIZE}&startIndex={start}"
        );
        let page = feed::parse_nvd(&transport.get(&url).await?)?;
        if page.skipped > 0 {
            tracing::debug!(skipped = page.skipped, "advisory feed: NVD records skipped");
        }
        all.extend(page.cves);
        start = page.start_index + page.results_per_page.max(1);
        if start >= page.total_results {
            all.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
            all.dedup_by(|a, b| a.cve_id == b.cve_id);
            return Ok(all);
        }
    }
    Err(format!("NVD pagination exceeded {MAX_PAGES} pages"))
}

/// `jitter` is 0..JITTER_SECS; passed in so the schedule is testable.
fn next_delay(report: &FeedCycleReport, jitter: u64) -> Duration {
    if report.skipped_for_consent {
        return Duration::from_secs(CONSENT_RECHECK_SECS);
    }
    let failed = matches!(report.nvd, Some(Err(_))) || matches!(report.kev, Some(Err(_)));
    if failed {
        Duration::from_secs(RETRY_SECS)
    } else {
        Duration::from_secs(REFRESH_SECS + jitter)
    }
}

fn jitter() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    nanos % JITTER_SECS
}

/// Spawn the supervised feed loop.
pub fn spawn_advisory_feed(supervisor: &TaskSupervisor, state: AppState) {
    supervisor.spawn("advisory-feed", move || {
        let state = state.clone();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_SECS)).await;
            tracing::info!("advisory feed starting");
            loop {
                let consent = match consent::load(&state.switch_store).await {
                    Ok(r) => r.consent,
                    Err(e) => {
                        tracing::warn!(error = %e, "advisory feed: consent unreadable; treating as unanswered");
                        FeedConsent::Unanswered
                    }
                };
                let report = match build_client() {
                    Ok(client) => {
                        run_feed_cycle(consent, &ReqwestTransport { client }, &state.advisory_store, now_unix(), PAGE_GAP).await
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "advisory feed: http client unavailable");
                        FeedCycleReport { nvd: Some(Err(e.clone())), kev: Some(Err(e)), ..Default::default() }
                    }
                };
                if !report.skipped_for_consent {
                    tracing::info!(nvd = ?report.nvd, kev = ?report.kev, "advisory feed cycle complete");
                }
                tokio::time::sleep(next_delay(&report, jitter())).await;
            }
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::feed::fixtures;
    use std::sync::Mutex;

    #[test]
    fn user_agent_discloses_nothing_about_the_installation() {
        assert_eq!(FEED_USER_AGENT, "ion-drift");
    }
    use tempfile::NamedTempFile;

    struct MockTransport {
        calls: Mutex<Vec<String>>,
        nvd: Result<Vec<u8>, String>,
        kev: Result<Vec<u8>, String>,
    }

    impl MockTransport {
        fn new(nvd: Result<Vec<u8>, String>, kev: Result<Vec<u8>, String>) -> Self {
            Self { calls: Mutex::new(Vec::new()), nvd, kev }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl FeedTransport for MockTransport {
        async fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.calls.lock().unwrap().push(url.to_string());
            if url.starts_with(NVD_URL) {
                self.nvd.clone()
            } else if url == KEV_URL {
                self.kev.clone()
            } else {
                Err(format!("unexpected url {url}"))
            }
        }
    }

    async fn store() -> (NamedTempFile, AdvisoryStore) {
        let f = NamedTempFile::new().unwrap();
        let s = AdvisoryStore::new(f.path()).await.unwrap();
        (f, s)
    }

    const NO_GAP: Duration = Duration::ZERO;

    #[tokio::test]
    async fn no_request_is_made_until_consent_is_on() {
        let (_f, store) = store().await;
        let t = MockTransport::new(Ok(fixtures::nvd_body()), Ok(fixtures::kev_body()));
        for consent in [FeedConsent::Unanswered, FeedConsent::Off] {
            let report = run_feed_cycle(consent, &t, &store, 1, NO_GAP).await;
            assert!(report.skipped_for_consent);
        }
        assert!(t.calls().is_empty(), "no outbound request before consent");
        assert!(store.feed_states().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn consent_on_stores_nvd_and_kev() {
        let (_f, store) = store().await;
        let t = MockTransport::new(Ok(fixtures::nvd_body()), Ok(fixtures::kev_body()));
        let report = run_feed_cycle(FeedConsent::On, &t, &store, 100, NO_GAP).await;
        assert_eq!(report.nvd, Some(Ok(1)));
        assert_eq!(report.kev, Some(Ok(1)));
        assert_eq!(store.list_feed_cves().await.unwrap()[0].cve_id, "CVE-2026-86060");
        assert_eq!(store.list_feed_kev().await.unwrap()[0].cve_id, "CVE-2026-86060");
    }

    #[tokio::test]
    async fn only_the_two_constant_hosts_are_contacted() {
        let (_f, store) = store().await;
        let t = MockTransport::new(Ok(fixtures::nvd_body()), Ok(fixtures::kev_body()));
        run_feed_cycle(FeedConsent::On, &t, &store, 100, NO_GAP).await;
        for url in t.calls() {
            assert!(url.starts_with(NVD_URL) || url == KEV_URL, "unexpected host: {url}");
        }
    }

    #[tokio::test]
    async fn failed_fetch_keeps_last_known_good() {
        let (_f, store) = store().await;
        let good = MockTransport::new(Ok(fixtures::nvd_body()), Ok(fixtures::kev_body()));
        run_feed_cycle(FeedConsent::On, &good, &store, 100, NO_GAP).await;

        let bad = MockTransport::new(Err("HTTP 503".into()), Err("timeout".into()));
        let report = run_feed_cycle(FeedConsent::On, &bad, &store, 200, NO_GAP).await;
        assert!(matches!(report.nvd, Some(Err(_))));

        assert_eq!(store.list_feed_cves().await.unwrap().len(), 1);
        assert_eq!(store.list_feed_kev().await.unwrap().len(), 1);
        let nvd = store.feed_states().await.unwrap().into_iter().find(|s| s.source == "nvd").unwrap();
        assert_eq!(nvd.last_success_at, Some(100));
        assert_eq!(nvd.last_attempt_at, 200);
        assert_eq!(nvd.last_error.as_deref(), Some("HTTP 503"));
    }

    #[tokio::test]
    async fn nvd_failure_does_not_block_kev() {
        let (_f, store) = store().await;
        let t = MockTransport::new(Err("HTTP 503".into()), Ok(fixtures::kev_body()));
        let report = run_feed_cycle(FeedConsent::On, &t, &store, 100, NO_GAP).await;
        assert!(matches!(report.nvd, Some(Err(_))));
        assert_eq!(report.kev, Some(Ok(1)));
    }

    #[test]
    fn next_delay_follows_the_outcome() {
        let skipped = FeedCycleReport { skipped_for_consent: true, ..Default::default() };
        assert_eq!(next_delay(&skipped, 0), Duration::from_secs(CONSENT_RECHECK_SECS));
        let failed = FeedCycleReport { nvd: Some(Err("x".into())), kev: Some(Ok(1)), ..Default::default() };
        assert_eq!(next_delay(&failed, 0), Duration::from_secs(RETRY_SECS));
        let ok = FeedCycleReport { nvd: Some(Ok(1)), kev: Some(Ok(1)), ..Default::default() };
        assert_eq!(next_delay(&ok, 0), Duration::from_secs(REFRESH_SECS));
        assert_eq!(next_delay(&ok, 1_799), Duration::from_secs(REFRESH_SECS + 1_799));
    }
}
