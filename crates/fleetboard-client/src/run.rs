//! Starting and stopping the client: the sampler thread plus the HTTP server, ended by whatever
//! future the caller passes (Ctrl-C and SIGTERM for the console, the SCM's Stop for the service).

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::Context;

use crate::config::ClientConfig;
use crate::http::{router, AppState};
use crate::{gpu, sampler};

/// Run until `shutdown` completes; returns when everything has stopped.
pub fn serve(
    cfg: ClientConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let addr = cfg.bind_addr()?;
    let latest: sampler::Latest = Arc::new(RwLock::new(None));
    let stop = Arc::new(AtomicBool::new(false));
    let collectors = gpu::detect(cfg.gpu);
    let state = AppState {
        latest: latest.clone(),
        token: cfg.token.trim().into(),
        allowed_hosts: Arc::new(cfg.allowed_hosts.clone()),
        hostname: sysinfo::System::host_name().unwrap_or_else(|| "unknown".into()),
    };
    let sampler = sampler::Sampler::new(&cfg, collectors);
    let sampler_thread = {
        let (latest, stop) = (latest.clone(), stop.clone());
        std::thread::Builder::new()
            .name("sampler".into())
            .spawn(move || sampler::run(sampler, latest, stop))?
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let served = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("can't listen on {addr}"))?;
        tracing::info!("fleetboard-client {} listening on {addr}", crate::VERSION);
        axum::serve(listener, router(state))
            .with_graceful_shutdown(shutdown)
            .await?;
        anyhow::Ok(())
    });

    stop.store(true, Ordering::Relaxed); // tell the sampler to finish its nap, whatever happened above
    let _ = sampler_thread.join();
    served?;
    tracing::info!("stopped");
    Ok(())
}

/// Ctrl-C everywhere, plus SIGTERM on Unix (what systemd sends).
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    tracing::info!("stop requested");
}
