#![no_main]
//! Fuzz the SNMP PortList bitmap decoder. The portlist OCTET STRING comes
//! straight from polled-device SNMP responses (Q-BRIDGE-MIB), so it is raw
//! attacker-influenceable bytes — the only binary parse path in mikrotik-core.
use libfuzzer_sys::fuzz_target;
use mikrotik_core::snmp_client::fuzz_decode_portlist;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode_portlist(data);
});
