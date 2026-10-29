//! The two routes and their hardening. Everything the server could ever ask for is a GET, so any
//! other method is refused, bodies are capped, and every answer carries no-store and nosniff.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use fleetboard_proto::{Health, SCHEMA};
use serde_json::json;

use crate::auth::token_matches;
use crate::sampler::Latest;

/// What the handlers need: the latest snapshot, the token and the optional Host allow-list.
#[derive(Clone)]
pub struct AppState {
    pub latest: Latest,
    pub token: Arc<str>,
    pub allowed_hosts: Arc<Vec<String>>,
    pub hostname: String,
}

/// The whole app: routes, body limit and the header middleware.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/stats", get(stats))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(1024)) // nobody should send us a body at all
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Liveness: who this is, without the token.
async fn healthz(State(st): State<AppState>) -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        schema: SCHEMA,
        agent: crate::VERSION.into(),
        hostname: st.hostname.clone(),
    })
}

/// The latest snapshot, for the holder of the token; 503 until the sampler has two readings.
async fn stats(State(st): State<AppState>, req: Request<Body>) -> Response {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if !token_matches(auth, &st.token) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({"detail": "Wrong or missing token"})),
        )
            .into_response();
    }
    let snap = st.latest.read().ok().and_then(|s| s.clone());
    match snap {
        Some(s) => Json(s).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": "Warming up: no sample yet"})),
        )
            .into_response(),
    }
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"detail": "Not found"}))).into_response()
}

/// Before: refuse a Host that isn't on the allow-list (when one is set). After: add the headers
/// every answer gets.
async fn guard(State(st): State<AppState>, req: Request<Body>, next: Next) -> Response {
    if !st.allowed_hosts.is_empty() {
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let bare = host
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host)
            .trim_matches(['[', ']']); // drop the port
        if !st
            .allowed_hosts
            .iter()
            .any(|a| a.eq_ignore_ascii_case(bare) || a.eq_ignore_ascii_case(host))
        {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"detail": "Wrong address"})),
            )
                .into_response();
        }
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use fleetboard_proto::Snapshot;
    use std::sync::RwLock;
    use tower::ServiceExt;

    const T: &str = "abcdefghijklmnopqrstuvwxyz123456";

    fn app(latest: Option<Snapshot>, allowed: Vec<&str>) -> Router {
        router(AppState {
            latest: Arc::new(RwLock::new(latest)),
            token: T.into(),
            allowed_hosts: Arc::new(allowed.into_iter().map(String::from).collect()),
            hostname: "testbox".into(),
        })
    }

    fn get(path: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut b = Request::builder().uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn healthz_needs_no_token_and_carries_the_hardening_headers() {
        let res = app(None, vec![])
            .oneshot(get("/healthz", &[]))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(res.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        let body = to_bytes(res.into_body(), 4096).await.unwrap();
        let health: Health = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.hostname, "testbox");
        assert_eq!(health.schema, SCHEMA);
    }

    #[tokio::test]
    async fn stats_wants_the_token_and_says_warming_up_before_the_first_sample() {
        let a = app(None, vec![]);
        assert_eq!(
            a.clone()
                .oneshot(get("/stats", &[]))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            a.clone()
                .oneshot(get("/stats", &[("authorization", "Bearer wrong")]))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let res = a
            .oneshot(get("/stats", &[("authorization", &format!("Bearer {T}"))]))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn other_methods_and_unknown_paths_are_refused() {
        let a = app(None, vec![]);
        let post = Request::builder()
            .method("POST")
            .uri("/stats")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            a.clone().oneshot(post).await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            a.oneshot(get("/nothing", &[])).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn the_host_allow_list_blocks_other_names() {
        let a = app(None, vec!["rds1.lan"]);
        assert_eq!(
            a.clone()
                .oneshot(get("/healthz", &[("host", "evil.example:9280")]))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            a.oneshot(get("/healthz", &[("host", "RDS1.lan:9280")]))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}
