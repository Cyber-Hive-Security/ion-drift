//! Advisory correlation — exposure and exploitation state for known issues.
//!
//! Drift core carries no advisory content. The advisories themselves, the
//! surfaces they apply to, and the signals that corroborate them all arrive as
//! catalog data ([`catalog`]) and land in `advisory.db`. Core only knows how to
//! emit a fixed set of behavioural signal ids ([`signals`]) and how to turn
//! observed signals into exploitation state ([`exploitation`]) — it never names
//! a CVE in a Rust literal.
//!
//! That split is what keeps the correlation module-agnostic: adding an advisory
//! is a catalog edit, and teaching Drift a new signal is the only change that
//! needs code.

pub mod catalog;
pub mod consent;
pub mod device_pass;
pub mod exploitation;
pub mod exposure;
pub mod feed;
pub mod signals;
pub mod sustained;
pub mod version;
pub mod vulnerable;
