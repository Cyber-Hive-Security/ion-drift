use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ion_drift_web::task_supervisor::{TaskState, TaskSupervisor};

#[tokio::test]
async fn supervisor_restarts_panicked_task() {
    let supervisor = TaskSupervisor::with_backoff(
        Duration::from_millis(100),
        Duration::from_millis(200),
        Duration::from_secs(60),
    );
    let counter = Arc::new(AtomicU32::new(0));
    let c = counter.clone();

    supervisor.spawn("panic_task", move || {
        let c = c.clone();
        Box::pin(async move {
            let n = c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                panic!("first run panics");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        })
    });

    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(counter.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn supervisor_restarts_task_that_returns() {
    let supervisor = TaskSupervisor::with_backoff(
        Duration::from_millis(100),
        Duration::from_millis(200),
        Duration::from_secs(60),
    );
    let counter = Arc::new(AtomicU32::new(0));
    let c = counter.clone();

    supervisor.spawn("return_task", move || {
        let c = c.clone();
        Box::pin(async move {
            c.fetch_add(1, Ordering::SeqCst);
        })
    });

    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(counter.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn supervisor_reports_task_status() {
    let supervisor = TaskSupervisor::with_backoff(
        Duration::from_millis(100),
        Duration::from_millis(200),
        Duration::from_secs(60),
    );

    supervisor.spawn("healthy_task", move || {
        Box::pin(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    let statuses = supervisor.status().await;
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].name, "healthy_task");
    assert!(matches!(
        statuses[0].state,
        TaskState::Running | TaskState::Restarting { .. }
    ));
}

#[tokio::test]
async fn supervisor_handles_multiple_tasks() {
    let supervisor = TaskSupervisor::with_backoff(
        Duration::from_millis(100),
        Duration::from_millis(200),
        Duration::from_secs(60),
    );

    for i in 0..5 {
        let name = format!("task_{i}");
        supervisor.spawn(&name, move || {
            Box::pin(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            })
        });
    }

    tokio::time::sleep(Duration::from_millis(150)).await;
    let statuses = supervisor.status().await;
    assert_eq!(statuses.len(), 5);
}
