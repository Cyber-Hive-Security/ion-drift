# Problem Fix Item 20 — Task Reliability Tests

## Priority: P1 | Difficulty: L | Safe for AI: Partial | Needs human review: Yes

## Problem

The `TaskSupervisor` was added to restart panicked/crashed background tasks, but there are no tests verifying:
1. A panicking task gets restarted
2. Backoff increases on repeated failures
3. Backoff resets after healthy running
4. Task status reporting works correctly
5. Multiple tasks can run concurrently without interference

## Goal

Add unit tests for `TaskSupervisor` that verify restart behavior, backoff logic, and status reporting.

## Scope

### 1. Test: panic recovery

```rust
#[tokio::test]
async fn supervisor_restarts_panicked_task() {
    let supervisor = TaskSupervisor::new();
    let counter = Arc::new(AtomicU32::new(0));
    let c = counter.clone();

    supervisor.spawn("test_panic", move || {
        let c = c.clone();
        Box::pin(async move {
            let count = c.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                panic!("first run panics");
            }
            // Second run: stay alive briefly then return
            tokio::time::sleep(Duration::from_millis(100)).await;
        })
    });

    // Wait for restart (initial backoff is 5s, but for tests we might
    // need to either: lower the backoff constants, or wait longer)
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert!(counter.load(Ordering::SeqCst) >= 2, "task should have been restarted");
}
```

**Important:** The current `INITIAL_BACKOFF` is 5 seconds. For tests, either:
- Accept that tests take ~6-7 seconds (fine for CI)
- Add a constructor `TaskSupervisor::with_backoff(initial, max, healthy_reset)` for test configurability

### 2. Test: normal return recovery

```rust
#[tokio::test]
async fn supervisor_restarts_task_that_returns() {
    let supervisor = TaskSupervisor::new();
    let counter = Arc::new(AtomicU32::new(0));
    let c = counter.clone();

    supervisor.spawn("test_return", move || {
        let c = c.clone();
        Box::pin(async move {
            c.fetch_add(1, Ordering::SeqCst);
            // Return immediately — supervisor should restart
        })
    });

    tokio::time::sleep(Duration::from_secs(7)).await;
    assert!(counter.load(Ordering::SeqCst) >= 2);
}
```

### 3. Test: status reporting

```rust
#[tokio::test]
async fn supervisor_reports_task_status() {
    let supervisor = TaskSupervisor::new();

    supervisor.spawn("healthy_task", move || {
        Box::pin(async move {
            loop { tokio::time::sleep(Duration::from_secs(3600)).await; }
        })
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let statuses = supervisor.status().await;
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].name, "healthy_task");
    assert!(matches!(statuses[0].state, TaskState::Running));
    assert_eq!(statuses[0].restart_count, 0);
}
```

### 4. Test: multiple concurrent tasks

```rust
#[tokio::test]
async fn supervisor_handles_multiple_tasks() {
    let supervisor = TaskSupervisor::new();

    for i in 0..5 {
        let name = format!("task_{i}");
        supervisor.spawn(&name, move || {
            Box::pin(async move {
                loop { tokio::time::sleep(Duration::from_secs(3600)).await; }
            })
        });
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let statuses = supervisor.status().await;
    assert_eq!(statuses.len(), 5);
    for s in &statuses {
        assert!(matches!(s.state, TaskState::Running));
    }
}
```

### 5. (Optional) Test: backoff configurability

If `TaskSupervisor::with_backoff()` is added:

```rust
#[tokio::test]
async fn supervisor_uses_exponential_backoff() {
    let supervisor = TaskSupervisor::with_backoff(
        Duration::from_millis(100),  // initial
        Duration::from_millis(400),  // max
        Duration::from_secs(60),     // healthy reset
    );

    let timestamps = Arc::new(Mutex::new(Vec::new()));
    let ts = timestamps.clone();

    supervisor.spawn("backoff_test", move || {
        let ts = ts.clone();
        Box::pin(async move {
            ts.lock().unwrap().push(Instant::now());
            // Return immediately to trigger restart
        })
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let ts = timestamps.lock().unwrap();
    assert!(ts.len() >= 3, "should have restarted at least 3 times");
    // Verify increasing gaps between restarts
    if ts.len() >= 3 {
        let gap1 = ts[1] - ts[0];
        let gap2 = ts[2] - ts[1];
        assert!(gap2 > gap1, "backoff should increase");
    }
}
```

## Key files

| File | Action |
|------|--------|
| `crates/ion-drift-web/src/task_supervisor.rs` | Optionally add `with_backoff()` constructor |
| `crates/ion-drift-web/tests/task_supervisor_test.rs` | NEW — all tests |

## Constraints

- Tests must complete in < 30 seconds total
- Use `tokio::test` runtime
- Do NOT test the actual background tasks (traffic_poller, etc.) — only test the supervisor mechanism itself
- If adding `with_backoff()`, keep the default `new()` unchanged

## Verification

1. `cargo test -p ion-drift-web task_supervisor` passes
2. Panic recovery is verified
3. Status reporting is verified
4. At least 4 test cases exist
