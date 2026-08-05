//! Confusable / homograph domain detection — a second catalog-driven detector.
//!
//! Like the advisory engine, core carries no watchlist content: brands arrive
//! as catalog data (bundled seed + operator overlay) and land in `dns.db`.
//! Core only knows how to normalize a name, compute a UTS #39 skeleton, and
//! compare — adding a brand is a catalog edit, never a code change.

pub mod catalog;
pub mod skeleton;
