use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;

pub trait DnsResolver: Send + Sync {
    fn reverse_lookup<'a>(
        &'a self,
        ip: IpAddr,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>>;
}

pub struct HickoryResolver {
    resolver: Resolver<TokioConnectionProvider>,
}

impl HickoryResolver {
    pub fn new(dns_server: Option<&str>) -> anyhow::Result<Self> {
        let config = if let Some(server) = dns_server {
            let addr: IpAddr = server
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid dns_server IP {server:?}: {e}"))?;
            let ns_group = NameServerConfigGroup::from_ips_clear(&[addr], 53, true);
            ResolverConfig::from_parts(None, Vec::new(), ns_group)
        } else {
            tracing::debug!("no dns_server configured, using system resolver for PTR lookups");
            ResolverConfig::default()
        };
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(500);
        opts.attempts = 1;
        let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();
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
            out.iter()
                .next()
                .map(|name| name.to_string().trim_end_matches('.').to_string())
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
