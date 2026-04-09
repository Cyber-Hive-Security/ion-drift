use std::collections::HashMap;
use std::sync::Arc;

use ion_drift_storage::SwitchStore;
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;

use crate::device_manager::{DeviceClient, DeviceEntry, DeviceManager};

/// Tracks running per-device poller tasks and provides start/stop lifecycle management.
///
/// Each device gets a single poller task matched to its `device_type`. The task runs
/// in a loop until a cancellation signal is sent via a `watch` channel.
pub struct PollerRegistry {
    /// Map of device_id -> (cancellation sender, task handle).
    tasks: HashMap<String, (watch::Sender<bool>, JoinHandle<()>)>,
}

impl PollerRegistry {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
        }
    }

    /// Start a poller for a single device. If one is already running for this device_id,
    /// it is stopped first.
    pub fn start_poller(
        &mut self,
        entry: &DeviceEntry,
        device_manager: Arc<RwLock<DeviceManager>>,
        switch_store: Arc<SwitchStore>,
        ros_queue: Option<crate::router_queue::RouterQueue>,
    ) {
        let device_id = entry.record.id.clone();

        // Stop existing poller if any
        self.stop_poller(&device_id);

        let (cancel_tx, cancel_rx) = watch::channel(false);

        let handle = match &entry.client {
            DeviceClient::RouterOs(_client) => {
                let queue = ros_queue.expect("RouterOS device requires a queue — caller must provide one");
                let device_id = device_id.clone();
                let poll_interval = entry.record.poll_interval_secs as u64;
                let device_name = entry.record.name.clone();

                tracing::info!(
                    id = %device_id,
                    name = %device_name,
                    interval_secs = poll_interval,
                    "starting switch poller (queued)"
                );

                tokio::spawn(async move {
                    crate::switch_poller::run_switch_poller(
                        device_id,
                        queue,
                        switch_store,
                        device_manager,
                        poll_interval,
                        cancel_rx,
                    )
                    .await;
                })
            }
            DeviceClient::Snmp(client) => {
                let client = client.clone();
                let device_id = device_id.clone();
                let poll_interval = entry.record.poll_interval_secs as u64;
                let device_name = entry.record.name.clone();

                tracing::info!(
                    id = %device_id,
                    name = %device_name,
                    interval_secs = poll_interval,
                    "starting SNMP poller (dynamic)"
                );

                tokio::spawn(async move {
                    crate::snmp_poller::run_snmp_poller(
                        device_id,
                        client,
                        switch_store,
                        device_manager,
                        poll_interval,
                        cancel_rx,
                    )
                    .await;
                })
            }
            DeviceClient::SwOs(client) => {
                let client = client.clone();
                let device_id = device_id.clone();
                let poll_interval = entry.record.poll_interval_secs as u64;
                let device_name = entry.record.name.clone();

                tracing::info!(
                    id = %device_id,
                    name = %device_name,
                    interval_secs = poll_interval,
                    "starting SwOS poller (dynamic)"
                );

                tokio::spawn(async move {
                    crate::swos_poller::run_swos_poller(
                        device_id,
                        client,
                        switch_store,
                        device_manager,
                        poll_interval,
                        cancel_rx,
                    )
                    .await;
                })
            }
        };

        self.tasks.insert(device_id, (cancel_tx, handle));
    }

    /// Stop the poller for a given device_id. Sends cancellation and aborts the task.
    pub fn stop_poller(&mut self, device_id: &str) {
        if let Some((cancel_tx, handle)) = self.tasks.remove(device_id) {
            // Signal cancellation — the poller loop will exit on next tick
            let _ = cancel_tx.send(true);
            // Also abort in case the task is sleeping in a long interval
            handle.abort();
            tracing::info!(device = %device_id, "poller stopped");
        }
    }

    /// Check if a poller is running for a device.
    pub fn has_poller(&self, device_id: &str) -> bool {
        self.tasks.contains_key(device_id)
    }
}
