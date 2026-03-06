//! Topology inference engine — probabilistic MAC attachment resolution.
//!
//! Replaces the deterministic priority-based MAC binding with a weighted
//! candidate scoring pipeline over a constrained infrastructure graph.

pub mod graph;
pub mod candidates;
pub mod scoring;
pub mod state;
pub mod resolver;
