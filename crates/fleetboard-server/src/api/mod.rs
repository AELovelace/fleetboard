//! The HTTP surface: embedded dashboard assets, `/healthz`, the hosts API, the live stream and
//! history. Every path is relative-friendly (the proxy strips `/remote/<slug>`), every error is
//! `{"detail": "..."}` so one small `api()` helper in the browser handles them all, and every
//! answer carries no-store and nosniff.

pub mod assets;
pub mod errors;
pub mod history;
pub mod hosts;
pub mod live;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::{Json, Response};
use axum::routing::get;
use axum::Router;
use serde_json::json;

use crate::db::Db;
use crate::poller::Poller;

/// Shared by every handler.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub poller: Arc<Poller>,
    pub token_set: bool,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/hosts", get(hosts::list).post(hosts::create))
        .route("/api/hosts/check", axum::routing::post(hosts::check))
        .route(
            "/api/hosts/{id}",
            axum::routing::put(hosts::update).delete(hosts::remove),
        )
        .route("/api/live", get(live::stream))
        .route("/api/ring", get(live::ring))
        .route("/api/history", get(history::history))
        .fallback(assets::serve)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(headers))
        .with_state(state)
}

/// Liveness for installers and curl: counts only, nothing secret.
async fn healthz(State(st): State<AppState>) -> Json<serde_json::Value> {
    let (hosts, up) = st.poller.host_count();
    let db = st.db.sample_count().map(|_| "ok").unwrap_or("error");
    Json(json!({"status": "ok", "version": crate::VERSION, "hosts": hosts, "up": up, "db": db}))
}

/// The headers every answer gets; the assets module sets its own Cache-Control first.
async fn headers(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    res
}

/// Who did it, for the audit log: the proxy's X-Forwarded-For, else "local".
pub fn who(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "local".into())
}
