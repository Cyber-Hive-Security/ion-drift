use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};

pub trait DnsResolver: Send + Sync {
    fn reverse_lookup<'a>(
        &'a self,
        ip: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>>;
}

pub struct HickoryResolver {
    resolver: TokioResolver,
}

impl HickoryResolver {
    pub fn new(dns_server: Option<&str>) -> anyhow::Result<Self> {
        let mut builder = if let Some(server) = dns_server {
            let addr: IpAddr = server
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid dns_server IP {server:?}: {e}"))?;
            let ns = vec![NameServerConfig::udp_and_tcp(addr)];
            let config = ResolverConfig::from_parts(None, Vec::new(), ns);
            Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        } else {
            tracing::debug!("no dns_server configured, using system resolver for PTR lookups");
            TokioResolver::builder_tokio()
                .map_err(|e| anyhow::anyhow!("failed to read system DNS config: {e}"))?
        };
        let opts = builder.options_mut();
        opts.timeout = Duration::from_millis(500);
        opts.attempts = 1;
        let resolver = builder
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build DNS resolver: {e}"))?;
        Ok(Self { resolver })
    }
}

impl DnsResolver for HickoryResolver {
    fn reverse_lookup<'a>(
        &'a self,
        ip: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move {
            let out = tokio::time::timeout(Duration::from_millis(500), self.resolver.reverse_lookup(ip))
                .await
                .ok()?
                .ok()?;
            out.answers().iter().find_map(|r| match &r.data {
                RData::PTR(name) => Some(name.to_string().trim_end_matches('.').to_string()),
                _ => None,
            })
        })
    }
}

pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn reverse_lookup<'a>(
        &'a self,
        _ip: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async { None })
    }
}

pub fn build_dns_resolver(dns_server: Option<&str>) -> Arc<dyn DnsResolver> {
    match HickoryResolver::new(dns_server) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            tracing::warn!("failed to build hickory DNS resolver, falling back to no-op resolver: {e}");
            Arc::new(SystemResolver)
        }
    }
}
