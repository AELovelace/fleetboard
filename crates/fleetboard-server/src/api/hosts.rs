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
use fleetboard_proto::HostLive;

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
    let row = add_host(&st, &who(&headers), &body.name, &body.address, "").await?;
    Ok((StatusCode::CREATED, Json(json!(row))))
}

/// Add a host (shared by the dashboard and `/api/v1`): check it answers, save, audit, poll once.
/// `note` is appended to the audit detail (the API's "reason").
pub async fn add_host(
    st: &AppState,
    who: &str,
    name: &str,
    address: &str,
    note: &str,
) -> Result<Option<HostLive>, ApiError> {
    let name = clean_name(name)?;
    let addr = HostAddr::parse(address).map_err(ApiError::bad)?;
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
    st.db.audit(
        now,
        who,
        "host.add",
        &host.name,
        &with_note(&host.address, note),
    )?;
    st.poller.configure(st.db.list_hosts()?);
    st.poller.poll_once().await;
    Ok(st.poller.view().into_iter().find(|h| h.id == host.id))
}

/// The audit detail with the reason after it, when there is one.
fn with_note(detail: &str, note: &str) -> String {
    if note.is_empty() {
        detail.to_string()
    } else {
        format!("{detail}; reason: {note}")
    }
}

/// `PUT /api/hosts/{id}`: rename, move or enable/disable; a new address is checked first.
pub async fn update(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(patch): Json<HostPatch>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = change_host(&st, id, &who(&headers), &patch, "").await?;
    Ok(Json(json!(row)))
}

/// Rename, move or enable/disable one host (shared by the dashboard and `/api/v1`).
pub async fn change_host(
    st: &AppState,
    id: i64,
    who: &str,
    patch: &HostPatch,
    note: &str,
) -> Result<Option<HostLive>, ApiError> {
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
        who,
        "host.change",
        &host.name,
        &with_note(
            &format!(
                "{} {} enabled={} (was {} {} enabled={})",
                host.name, host.address, host.enabled, before.name, before.address, before.enabled
            ),
            note,
        ),
    )?;
    st.poller.configure(st.db.list_hosts()?);
    if host.enabled {
        st.poller.poll_once().await;
    }
    Ok(st.poller.view().into_iter().find(|h| h.id == id))
}

/// `DELETE /api/hosts/{id}`: the host and its history.
pub async fn remove(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    remove_host(&st, id, &who(&headers), "")?;
    Ok(StatusCode::NO_CONTENT)
}

/// Remove one host and all its history (shared by the dashboard and `/api/v1`).
pub fn remove_host(st: &AppState, id: i64, who: &str, note: &str) -> Result<Host, ApiError> {
    let host = st
        .db
        .get_host(id)?
        .ok_or_else(|| ApiError::not_found("No such host."))?;
    st.db.delete_host(id)?;
    st.db.audit(
        crate::now_unix(),
        who,
        "host.remove",
        &host.name,
        &with_note(&host.address, note),
    )?;
    st.poller.configure(st.db.list_hosts()?);
    Ok(host)
}
