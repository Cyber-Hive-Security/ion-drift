//! Thin adapters that let the module host use Drift's task supervisor and
//! secrets resolution without coupling the module API crate to Drift.

use std::sync::Arc;

use ion_drift_module_api::context::{BoxFuture, SecretResolver, TaskSpawner};

use crate::task_supervisor::TaskSupervisor;

/// Task spawner adapter that delegates to Drift's supervisor.
pub struct SupervisorSpawner {
    supervisor: TaskSupervisor,
}

impl SupervisorSpawner {
    pub fn new(supervisor: TaskSupervisor) -> Self {
        Self { supervisor }
    }
}

impl TaskSpawner for SupervisorSpawner {
    fn spawn(
        &self,
        name: &str,
        factory: Box<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static>,
    ) {
        let factory = Arc::new(factory);
        self.supervisor.spawn(name, move || {
            let f = factory.clone();
            Box::pin(async move { f().await })
        });
    }
}

/// Secret resolver that reads from process environment variables.
pub struct EnvSecretResolver;

impl SecretResolver for EnvSecretResolver {
    fn resolve(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}
