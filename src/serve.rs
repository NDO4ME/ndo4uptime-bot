//! The HTTP accept loop shared by every listener.
//!
//! `axum::serve` has no limits of its own, so a handful of slow or idle connections could hold the
//! process open. This loop adds what a service that may face the internet (status pages) needs:
//! a cap on simultaneous connections, a deadline for receiving request headers (also closing idle
//! keep-alive connections) and TCP_NODELAY. Live-update streams are unaffected: the deadline only
//! covers reading a request, not the response.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceExt;

const HEADER_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn run(listener: TcpListener, router: Router, max_conns: usize) {
    let slots = Arc::new(Semaphore::new(max_conns));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                // Out of file descriptors or a transient error: back off instead of spinning.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue; // over the cap: refuse by closing the socket
        };
        let _ = stream.set_nodelay(true);
        let router = router.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let svc = service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                router.clone().oneshot(req.map(Body::new))
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT)
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

/// Resolves on SIGINT or SIGTERM (`docker stop`).
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
