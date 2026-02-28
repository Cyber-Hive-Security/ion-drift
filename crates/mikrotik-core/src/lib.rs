pub mod behavior;
pub mod client;
pub mod error;
pub mod metrics;
pub mod resources;
pub mod speedtest;
pub mod switch_store;
pub mod tracker;
pub mod vlan_flows;
mod serde_helpers;

pub use behavior::BehaviorStore;
pub use client::{MikrotikClient, MikrotikConfig};
pub use error::MikrotikError;
pub use metrics::{
    ConnectionMetricsPoint, DropMetricsPoint, LogAggregate, MetricsPoint, MetricsStore,
    VlanMetricsPoint,
};
pub use speedtest::{ProviderResult, SpeedTestResult, SpeedTestStore};
pub use tracker::{LifetimeTraffic, TrafficTracker};
pub use vlan_flows::{VlanFlow, VlanFlowManager};
pub use resources::bridge::{BridgeHost, BridgePort, BridgeVlan};
pub use resources::ethernet::EthernetInterface;
pub use resources::logging::{
    CreateFilterRule, CreateLoggingAction, CreateLoggingRule, LoggingAction, LoggingRule,
    UpdateFilterRule,
};
pub use resources::neighbor::IpNeighbor;
pub use switch_store::SwitchStore;
