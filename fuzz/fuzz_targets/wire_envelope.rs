#![no_main]
//! Fuzz the module-host wire ingress: untrusted bytes arriving from a module
//! socket are deserialized into an `EventEnvelope` (see
//! `modules_registry/inbound.rs` -> `serde_json::from_slice::<EventEnvelope>`).
use ion_drift_module_api::wire::EventEnvelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Mirrors the real ingress path. We only care that it never panics /
    // aborts / OOMs on arbitrary input — a returned Err is fine.
    let _ = serde_json::from_slice::<EventEnvelope>(data);
});
