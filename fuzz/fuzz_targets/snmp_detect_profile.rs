#![no_main]
//! Fuzz SNMP vendor-profile detection. `sys_descr` is attacker-influenceable:
//! it is whatever string the polled device returns for sysDescr.0.
use libfuzzer_sys::fuzz_target;
use mikrotik_core::snmp_profile::detect_profile;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = detect_profile(s);
    }
});
