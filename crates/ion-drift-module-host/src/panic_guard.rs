//! A small tower layer that catches panics in module HTTP handlers and
//! returns HTTP 500 instead of propagating the panic up to the server.
//!
//! This wraps the module subrouter so that a misbehaving module cannot
//! bring down the whole Axum listener. `tower-http` does not ship a built-in
//! catch-panic layer, so we implement a minimal one using
//! `std::panic::AssertUnwindSafe` and `futures::FutureExt::catch_unwind`.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use futures::FutureExt;
use tower::{Layer, Service};

/// Layer that installs a panic-catching wrapper around an inner service.
#[derive(Clone, Default)]
pub struct PanicGuardLayer {
    module_name: String,
}

impl PanicGuardLayer {
    pub fn new(module_name: impl Into<String>) -> Self {
        Self {
            module_name: module_name.into(),
        }
    }
}

impl<S> Layer<S> for PanicGuardLayer {
    type Service = PanicGuard<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PanicGuard {
            inner,
            module_name: self.module_name.clone(),
        }
    }
}

/// Service that wraps an inner axum service and catches panics raised during
/// request handling.
#[derive(Clone)]
pub struct PanicGuard<S> {
    inner: S,
    module_name: String,
}

impl<S> Service<Request<Body>> for PanicGuard<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Clone to satisfy the `Clone` bound (tower's `ServiceBuilder` pattern).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let module_name = self.module_name.clone();

        Box::pin(async move {
            let future = AssertUnwindSafe(inner.call(req));
            match future.catch_unwind().await {
                Ok(result) => result,
                Err(payload) => {
                    let msg = panic_message(&payload);
                    tracing::error!(
                        module = %module_name,
                        panic = %msg,
                        "module request handler panicked"
                    );
                    let body = format!(
                        r#"{{"error":"module panic","module":"{}"}}"#,
                        module_name
                    );
                    let response = Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .expect("static response body is well-formed");
                    Ok(response)
                }
            }
        })
    }
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<opaque panic payload>".to_string()
    }
}
