use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::RwLock;

/// State of a supervised task.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Running,
    Restarting { attempt: u32, next_retry_secs: f64 },
    Failed { attempts: u32, last_error: String },
}

/// Status snapshot for a single supervised task.
#[derive(Debug, Clone, Serialize)]
pub struct TaskStatus {
    pub name: String,
    pub state: TaskState,
    pub restart_count: u32,
    pub uptime_secs: f64,
}

/// Internal per-task record.
struct TaskRecord {
    state: TaskState,
    restart_count: u32,
    started_at: Instant,
}

/// A simple task supervisor that wraps `tokio::spawn` with panic recovery
/// and exponential backoff restarts.
///
/// Each task is expected to run an infinite loop. If a task returns or panics,
/// the supervisor restarts it with increasing backoff (5s initial, 60s max).
/// After 5 minutes of healthy running, the backoff resets.
#[derive(Clone)]
pub struct TaskSupervisor {
    tasks: Arc<RwLock<HashMap<String, Arc<RwLock<TaskRecord>>>>>,
    initial_backoff: Duration,
    max_backoff: Duration,
    healthy_reset: Duration,
}

/// Backoff parameters.
const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const HEALTHY_RESET: Duration = Duration::from_secs(300); // 5 minutes

impl TaskSupervisor {
    pub fn new() -> Self {
        Self::with_backoff(INITIAL_BACKOFF, MAX_BACKOFF, HEALTHY_RESET)
    }

    pub fn with_backoff(
        initial_backoff: Duration,
        max_backoff: Duration,
        healthy_reset: Duration,
    ) -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            initial_backoff,
            max_backoff,
            healthy_reset,
        }
    }

    /// Spawn a supervised task.
    ///
    /// `name` — human-readable task name (for logging and status reporting).
    /// `task_fn` — a factory that produces a new future each time the task needs
    ///   to be (re)started. The future should run forever (infinite loop).
    ///   If it returns or panics, the supervisor restarts it.
    pub fn spawn<F>(&self, name: &str, task_fn: F)
    where
        F: Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'static,
    {
        let record = Arc::new(RwLock::new(TaskRecord {
            state: TaskState::Running,
            restart_count: 0,
            started_at: Instant::now(),
        }));

        // Register the task in our map.
        let tasks = self.tasks.clone();
        let task_name = name.to_string();
        {
            let tasks_clone = tasks.clone();
            let record_clone = record.clone();
            let name_clone = task_name.clone();
            let initial_backoff = self.initial_backoff;
            let max_backoff = self.max_backoff;
            let healthy_reset = self.healthy_reset;
            tokio::spawn(async move {
                // Register
                {
                    let mut map = tasks_clone.write().await;
                    map.insert(name_clone.clone(), record_clone.clone());
                }

                let task_fn = Arc::new(task_fn);
                let mut backoff = initial_backoff;

                loop {
                    // Mark as running
                    {
                        let mut rec = record_clone.write().await;
                        rec.state = TaskState::Running;
                        rec.started_at = Instant::now();
                    }

                    let start = Instant::now();
                    let fut = (task_fn)();

                    // Run the task, catching panics
                    let result = {
                        use futures::FutureExt;
                        std::panic::AssertUnwindSafe(fut).catch_unwind().await
                    };

                    let elapsed = start.elapsed();
                    let mut rec = record_clone.write().await;
                    rec.restart_count += 1;

                    match result {
                        Ok(()) => {
                            // Task returned normally (shouldn't happen for infinite loops)
                            tracing::error!(
                                task = %name_clone,
                                uptime_secs = elapsed.as_secs_f64(),
                                "task exited unexpectedly (returned Ok), will restart"
                            );
                        }
                        Err(panic_payload) => {
                            let panic_msg = if let Some(s) = panic_payload.downcast_ref::<String>() {
                                s.clone()
                            } else if let Some(s) = panic_payload.downcast_ref::<&str>() {
                                s.to_string()
                            } else {
                                "unknown panic".to_string()
                            };
                            tracing::error!(
                                task = %name_clone,
                                uptime_secs = elapsed.as_secs_f64(),
                                panic = %panic_msg,
                                "task panicked, will restart"
                            );
                        }
                    }

                    // Reset backoff if the task ran long enough to be considered healthy
                    if elapsed >= healthy_reset {
                        backoff = initial_backoff;
                    }

                    rec.state = TaskState::Restarting {
                        attempt: rec.restart_count,
                        next_retry_secs: backoff.as_secs_f64(),
                    };
                    drop(rec);

                    let restart_count = record_clone.read().await.restart_count;
                    tracing::info!(
                        task = %name_clone,
                        restart_count,
                        backoff_secs = backoff.as_secs_f64(),
                        "restarting task after backoff"
                    );

                    tokio::time::sleep(backoff).await;

                    // Exponential backoff: double up to max
                    backoff = (backoff * 2).min(max_backoff);
                }
            });
        }
    }

    /// Return a snapshot of all task statuses.
    pub async fn status(&self) -> Vec<TaskStatus> {
        let map = self.tasks.read().await;
        let mut statuses = Vec::with_capacity(map.len());
        for (name, record) in map.iter() {
            let rec = record.read().await;
            statuses.push(TaskStatus {
                name: name.clone(),
                state: rec.state.clone(),
                restart_count: rec.restart_count,
                uptime_secs: rec.started_at.elapsed().as_secs_f64(),
            });
        }
        statuses.sort_by(|a, b| a.name.cmp(&b.name));
        statuses
    }
}
