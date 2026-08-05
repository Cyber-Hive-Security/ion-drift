//! DNS cache poller — harvests every name the router resolves and runs the
//! confusable-domain skeleton match over it.
//!
//! Only sees devices that use the router as their resolver; the DNS deviation
//! detector already identifies the ones that do not. Observations are the
//! name→IP join key (`dns.db`), retained on the windowed count + prune model.

use std::collections::BTreeMap;
use std::time::Duration;

use mikrotik_core::resources::ip::DnsCacheEntry;

use crate::confusable::detector::{
    CONFUSABLE_MODULE, ConfusableHit, WatchIndex, build_finding, group_hits,
};
use crate::confusable::skeleton::{normalize_domain, skeleton_of};
use crate::router_queue::{Priority, QueuedRequest};
use crate::state::AppState;
use crate::task_supervisor::TaskSupervisor;

/// `router_queue` poller id for this module's `/ip/dns/cache` fetch. The queue
/// keys pending work by poller id, so this must not collide with another
/// submitter's.
const POLLER_ID: &str = "dns-cache";
/// Stagger past startup, same rationale as the advisory evaluator: do not
/// compete with the pollers while the snapshot is warming up.
const STARTUP_DELAY_SECS: u64 = 120;
/// Observation retention: long enough that "first seen" is meaningful for
/// investigation, pruned so old rows do not accumulate.
const OBSERVATION_RETENTION_SECS: i64 = 90 * 86400;
/// Hard ceiling on distinct observed names.
///
/// Retention alone does not bound this table: distinct names are
/// attacker-controlled and free to mint, so a 90-day window still admits
/// unbounded rows inside it. At roughly 150 bytes a row this ceiling costs
/// single-digit megabytes — affordable on appliance storage, and far below
/// what a DNS-tunnelling implant would otherwise write.
const MAX_DNS_OBSERVATIONS: usize = 50_000;

/// Spawn the supervised DNS cache polling loop.
pub fn spawn_dns_cache_poller(supervisor: &TaskSupervisor, state: AppState) {
    let interval_secs = state.config.polling.dns_cache_interval_secs;
    supervisor.spawn("dns-cache-poller", move || {
        let state = state.clone();
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_SECS)).await;
            tracing::info!(interval_secs, "dns cache poller starting");

            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                if let Err(e) = poll_once(&state).await {
                    tracing::warn!(error = %e, "dns-cache: cycle failed");
                }
            }
        })
    });
}

async fn poll_once(state: &AppState) -> Result<(), String> {
    let results = state
        .router_queue
        .submit(
            POLLER_ID,
            Priority::Low,
            vec![QueuedRequest::get("ip/dns/cache")],
        )
        .await
        .map_err(|e| format!("dns cache fetch failed: {e}"))?;
    let entries: Vec<DnsCacheEntry> = match results.first() {
        Some(Ok(v)) => serde_json::from_value(v.clone())
            .map_err(|e| format!("dns cache deserialize: {e}"))?,
        Some(Err(e)) => return Err(format!("dns cache fetch failed: {e}")),
        None => return Err("dns cache fetch returned no result".to_string()),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // One observation per name; addresses aggregated across its A/AAAA/CNAME
    // rows in this snapshot.
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for e in &entries {
        let name = normalize_domain(&e.name);
        if name.is_empty() {
            continue;
        }
        let addrs = by_name.entry(name).or_default();
        if let Some(data) = &e.data {
            addrs.push(data.clone());
        }
    }

    let index = WatchIndex::build(&state.dns_store.list_watchlist().await?);

    let mut hits: Vec<(ConfusableHit, Vec<String>)> = Vec::new();
    for (name, addresses) in &by_name {
        // One name failing to store must not cost the rest of the cycle, the
        // match pass, or the prune below.
        if let Err(e) = state
            .dns_store
            .upsert_observation(name, &skeleton_of(name), addresses, now)
            .await
        {
            tracing::warn!(error = %e, name = %name, "dns-cache: observation write failed");
        }
        // Match every cycle, not only on new names: upsert_finding dedups on
        // (module, finding_id), and re-matching lets a watchlist update catch
        // names still present in the cache.
        if let Some(hit) = index.match_name(name) {
            hits.push((hit, addresses.clone()));
        }
    }

    // Group before emitting: every subdomain of one lookalike registration is
    // one attacker asset and belongs in one finding.
    for group in group_hits(hits) {
        let finding = build_finding(&group, now);
        match state
            .findings_store
            .upsert_finding(CONFUSABLE_MODULE, &finding, None, None)
            .await
        {
            Ok(_) => tracing::warn!(
                suffix = %group.matched_suffix,
                resembles = %group.watchlist_domain,
                names = group.observed_names.len(),
                "confusable domain observed"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                suffix = %group.matched_suffix,
                "dns-cache: finding upsert failed"
            ),
        }
    }

    match state
        .dns_store
        .prune_observations(now - OBSERVATION_RETENTION_SECS)
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::debug!(count = n, "dns-cache: pruned stale observations"),
        Err(e) => tracing::warn!(error = %e, "dns-cache: prune failed"),
    }
    // Ceiling after retention: evicting is reported at warn, because hitting
    // the cap means something is minting names faster than they age out and
    // an operator should know.
    match state
        .dns_store
        .enforce_observation_cap(MAX_DNS_OBSERVATIONS)
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::warn!(
            count = n,
            cap = MAX_DNS_OBSERVATIONS,
            "dns-cache: evicted oldest observations at the storage ceiling"
        ),
        Err(e) => tracing::warn!(error = %e, "dns-cache: cap enforcement failed"),
    }
    Ok(())
}
