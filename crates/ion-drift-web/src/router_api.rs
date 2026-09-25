//! Router API abstraction for testability.
//!
//! `RouterApi` is the trait the web handlers depend on for live RouterOS data.
//! `AppState.mikrotik` holds a `dyn RouterApi` trait object rather than a
//! concrete [`mikrotik_core::MikrotikClient`], so handlers can be exercised
//! end-to-end against a mock in tests (see [`crate::testkit`]).
//!
//! The trait mirrors *exactly* the router surface the handlers call and adds no
//! behavior of its own. The production implementation for `MikrotikClient` is a
//! thin, logic-free delegation to the client's inherent methods; inherent
//! methods take precedence over trait methods in call syntax, so `self.foo()`
//! inside the impl calls the real client, never the trait method.

use async_trait::async_trait;

use mikrotik_core::MikrotikError;
use mikrotik_core::resources::connection::{
    ConnectionEntry, ConnectionTracking, FullConnectionEntry,
};
use mikrotik_core::resources::ethernet::EthernetInterface;
use mikrotik_core::resources::firewall::{FilterRule, MangleRule, NatRule};
use mikrotik_core::resources::interface::{Interface, MonitorTrafficEntry, VlanInterface};
use mikrotik_core::resources::ip::{ArpEntry, DhcpLease, DhcpServer, IpAddress, IpPool, Route};
use mikrotik_core::resources::log::LogEntry;
use mikrotik_core::resources::system::{SystemIdentity, SystemResource};
use mikrotik_core::vlan_flows::VlanFlow;

/// The set of live RouterOS operations the web handlers depend on.
///
/// Every method mirrors an inherent method on [`mikrotik_core::MikrotikClient`]
/// with the same name, arguments, and return type — this trait is a pure
/// seam for substituting a mock in tests, not a place for new logic.
#[async_trait]
pub trait RouterApi: Send + Sync {
    async fn arp_table(&self) -> Result<Vec<ArpEntry>, MikrotikError>;
    async fn connection_tracking(&self) -> Result<ConnectionTracking, MikrotikError>;
    async fn dhcp_leases(&self) -> Result<Vec<DhcpLease>, MikrotikError>;
    async fn dhcp_servers(&self) -> Result<Vec<DhcpServer>, MikrotikError>;
    async fn ethernet_interfaces(&self) -> Result<Vec<EthernetInterface>, MikrotikError>;
    async fn firewall_connections(
        &self,
        proplist: &str,
    ) -> Result<Vec<ConnectionEntry>, MikrotikError>;
    async fn firewall_connections_full(&self)
        -> Result<Vec<FullConnectionEntry>, MikrotikError>;
    async fn firewall_filter_rules(&self) -> Result<Vec<FilterRule>, MikrotikError>;
    async fn firewall_mangle_rules(&self) -> Result<Vec<MangleRule>, MikrotikError>;
    async fn firewall_nat_rules(&self) -> Result<Vec<NatRule>, MikrotikError>;
    async fn interfaces(&self) -> Result<Vec<Interface>, MikrotikError>;
    async fn ip_addresses(&self) -> Result<Vec<IpAddress>, MikrotikError>;
    async fn ip_pools(&self) -> Result<Vec<IpPool>, MikrotikError>;
    async fn ip_routes(&self) -> Result<Vec<Route>, MikrotikError>;
    async fn log_entries(&self) -> Result<Vec<LogEntry>, MikrotikError>;
    async fn monitor_traffic(
        &self,
        interface: &str,
    ) -> Result<Vec<MonitorTrafficEntry>, MikrotikError>;
    async fn system_identity(&self) -> Result<SystemIdentity, MikrotikError>;
    async fn system_resources(&self) -> Result<SystemResource, MikrotikError>;
    async fn vlan_interfaces(&self) -> Result<Vec<VlanInterface>, MikrotikError>;
    /// VLAN traffic-flow view. Delegates to
    /// [`mikrotik_core::VlanFlowManager::get_flows`], whose free-function
    /// signature takes a concrete `&MikrotikClient`; exposing it here keeps the
    /// `vlan_flows` handler working through the trait object.
    async fn vlan_flows(&self) -> Result<Vec<VlanFlow>, MikrotikError>;
}

#[async_trait]
impl RouterApi for mikrotik_core::MikrotikClient {
    async fn arp_table(&self) -> Result<Vec<ArpEntry>, MikrotikError> {
        self.arp_table().await
    }
    async fn connection_tracking(&self) -> Result<ConnectionTracking, MikrotikError> {
        self.connection_tracking().await
    }
    async fn dhcp_leases(&self) -> Result<Vec<DhcpLease>, MikrotikError> {
        self.dhcp_leases().await
    }
    async fn dhcp_servers(&self) -> Result<Vec<DhcpServer>, MikrotikError> {
        self.dhcp_servers().await
    }
    async fn ethernet_interfaces(&self) -> Result<Vec<EthernetInterface>, MikrotikError> {
        self.ethernet_interfaces().await
    }
    async fn firewall_connections(
        &self,
        proplist: &str,
    ) -> Result<Vec<ConnectionEntry>, MikrotikError> {
        self.firewall_connections(proplist).await
    }
    async fn firewall_connections_full(
        &self,
    ) -> Result<Vec<FullConnectionEntry>, MikrotikError> {
        self.firewall_connections_full().await
    }
    async fn firewall_filter_rules(&self) -> Result<Vec<FilterRule>, MikrotikError> {
        self.firewall_filter_rules().await
    }
    async fn firewall_mangle_rules(&self) -> Result<Vec<MangleRule>, MikrotikError> {
        self.firewall_mangle_rules().await
    }
    async fn firewall_nat_rules(&self) -> Result<Vec<NatRule>, MikrotikError> {
        self.firewall_nat_rules().await
    }
    async fn interfaces(&self) -> Result<Vec<Interface>, MikrotikError> {
        self.interfaces().await
    }
    async fn ip_addresses(&self) -> Result<Vec<IpAddress>, MikrotikError> {
        self.ip_addresses().await
    }
    async fn ip_pools(&self) -> Result<Vec<IpPool>, MikrotikError> {
        self.ip_pools().await
    }
    async fn ip_routes(&self) -> Result<Vec<Route>, MikrotikError> {
        self.ip_routes().await
    }
    async fn log_entries(&self) -> Result<Vec<LogEntry>, MikrotikError> {
        self.log_entries().await
    }
    async fn monitor_traffic(
        &self,
        interface: &str,
    ) -> Result<Vec<MonitorTrafficEntry>, MikrotikError> {
        self.monitor_traffic(interface).await
    }
    async fn system_identity(&self) -> Result<SystemIdentity, MikrotikError> {
        self.system_identity().await
    }
    async fn system_resources(&self) -> Result<SystemResource, MikrotikError> {
        self.system_resources().await
    }
    async fn vlan_interfaces(&self) -> Result<Vec<VlanInterface>, MikrotikError> {
        self.vlan_interfaces().await
    }
    async fn vlan_flows(&self) -> Result<Vec<VlanFlow>, MikrotikError> {
        mikrotik_core::VlanFlowManager::get_flows(self).await
    }
}
