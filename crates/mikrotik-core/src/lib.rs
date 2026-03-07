pub mod client;
pub mod error;
pub mod resources;
pub mod snmp_client;
pub mod swos_client;
pub mod tracker;
pub mod vlan_flows;
mod serde_helpers;

pub use client::{MikrotikClient, MikrotikConfig, DEFAULT_ROUTER_HOST, DEFAULT_ROUTER_PORT, DEFAULT_ROUTER_USERNAME};
pub use snmp_client::SnmpClient;
pub use swos_client::SwosClient;
pub use error::MikrotikError;
pub use tracker::{LifetimeTraffic, TrafficTracker};
pub use vlan_flows::{VlanFlow, VlanFlowManager};
pub use resources::bridge::{BridgeHost, BridgePort, BridgeVlan};
pub use resources::ethernet::EthernetInterface;
pub use resources::logging::{
    CreateFilterRule, CreateLoggingAction, CreateLoggingRule, LoggingAction, LoggingRule,
    UpdateFilterRule,
};
pub use resources::neighbor::IpNeighbor;
