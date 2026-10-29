//! The host list: see it, add, change, remove, and "does this address answer?". Adding or changing
//! an address first asks the host (like Mnemerynne's balancer settings), so a typo is refused with
//! the reason rather than saved as a permanently red card.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use super::errors::ApiError;
use super::{who, AppState};
use crate::addr::HostAddr;
use crate::db::Host;
use crate::poller::MAX_HOSTS;

#[derive(Deserialize)]
pub struct NewHost {
    pub name: String,
    pub address: String,
}

#[derive(Deserialize, Default)]
pub struct HostPatch {
    pub name: Option<String>,
    pub address: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct CheckBody {
    pub address: String,
}

/// A display name: 1-64 printable characters.
fn clean_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad("The name must be 1-64 printable characters."));
    }
    Ok(name.to_string())
}

/// `GET /api/hosts`: every host as the dashboard sees it, plus whether a token is configured.
pub async fn list(State(st): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({"hosts": st.poller.view(), "token_set": st.token_set}))
}

/// `POST /api/hosts/check`: does this address answer with our token? Never saves anything.
pub async fn check(
    State(st): State<AppState>,
    Json(body): Json<CheckBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let addr = HostAddr::parse(&body.address).map_err(ApiError::bad)?;
    let ok = st
        .poller
        .check(&addr)
        .await
        .map_err(|why| ApiError::bad(format!("{addr} {why}.")))?;
    Ok(Json(
        json!({"ok": true, "address": addr.to_string(), "latency_ms": ok.latency_ms, "hostname": ok.hostname, "agent": ok.agent}),
    ))
}

/// `POST /api/hosts`: check, then save, then poll once so the answer already has a card.
pub async fn create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<NewHost>,
) -> Result<impl IntoResponse, ApiError> {
    let name = clean_name(&body.name)?;
    let addr = HostAddr::parse(&body.address).map_err(ApiError::bad)?;
    if st.db.list_hosts()?.len() >= MAX_HOSTS {
        return Err(ApiError::bad(format!(
            "Fleetboard keeps at most {MAX_HOSTS} hosts."
        )));
    }
    st.poller
        .check(&addr)
        .await
        .map_err(|why| ApiError::bad(format!("Not saved: {addr} {why}.")))?;
    let now = crate::now_unix();
    let host = st.db.insert_host(&name, &addr.to_string(), now)?;
    st.db
        .audit(now, &who(&headers), "host.add", &host.name, &host.address)?;
    st.poller.configure(st.db.list_hosts()?);
    st.poller.poll_once().await;
    let row = st.poller.view().into_iter().find(|h| h.id == host.id);
    Ok((StatusCode::CREATED, Json(json!(row))))
}

/// `PUT /api/hosts/{id}`: rename, move or enable/disable; a new address is checked first.
pub async fn update(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(patch): Json<HostPatch>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut host: Host = st
        .db
        .get_host(id)?
        .ok_or_else(|| ApiError::not_found("No such host."))?;
    let before = host.clone();
    if let Some(name) = &patch.name {
        host.name = clean_name(name)?;
    }
    if let Some(address) = &patch.address {
        let addr = HostAddr::parse(address).map_err(ApiError::bad)?;
        host.address = addr.to_string();
    }
    if let Some(enabled) = patch.enabled {
        host.enabled = enabled;
    }
    let address_changed = host.address != before.address;
    if host.enabled && (address_changed || (!before.enabled && host.enabled)) {
        let addr = HostAddr::parse(&host.address).map_err(ApiError::bad)?;
        st.poller
            .check(&addr)
            .await
            .map_err(|why| ApiError::bad(format!("Not saved: {addr} {why}.")))?;
    }
    let now = crate::now_unix();
    st.db.update_host(&host, now)?;
    st.db.audit(
        now,
        &who(&headers),
        "host.change",
        &host.name,
        &format!(
            "{} {} enabled={} (was {} {} enabled={})",
            host.name, host.address, host.enabled, before.name, before.address, before.enabled
        ),
    )?;
    st.poller.configure(st.db.list_hosts()?);
    if host.enabled {
        st.poller.poll_once().await;
    }
    let row = st.poller.view().into_iter().find(|h| h.id == id);
    Ok(Json(json!(row)))
}

/// `DELETE /api/hosts/{id}`: the host and its history.
pub async fn remove(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let host = st
        .db
        .get_host(id)?
        .ok_or_else(|| ApiError::not_found("No such host."))?;
    st.db.delete_host(id)?;
    st.db.audit(
        crate::now_unix(),
        &who(&headers),
        "host.remove",
        &host.name,
        &host.address,
    )?;
    st.poller.configure(st.db.list_hosts()?);
    Ok(StatusCode::NO_CONTENT)
}
