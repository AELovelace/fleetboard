//! `/api/v1`: the service API Mnemerynne calls so Claude (through Mnemerynne's connector) can read
//! the fleet and propose changes a person approves.
//!
//! - **Auth**: `Authorization: Bearer fbt_…`, a service token made with
//!   `fleetboard-server token add` (see `crate::tokens`). Missing, unknown or revoked → 401.
//!   A `read` token may only read; actions need an `act` token, else 403 (and the refusal is
//!   audited). The shared client token is never accepted here, and these tokens never reach a
//!   client: a leak of one doesn't open the other.
//! - **Every call is logged** in `api_calls` (time, token name, method, path, status, ms).
//! - **Every action is audited** with who = `Mnemerynne/Claude (token <name>)` and the reason
//!   the proposal carried. Mnemerynne only calls an action after a person pressed *Run it*.
//! - **Shape**: lists are `{"total": n, "rows": [...]}` with flat rows, so Mnemerynne can page them
//!   and `find=` works; units are in the field names (`used_bytes`, `cpu_pct`, `temp_c`) and
//!   times are UTC ISO strings. Lists stay lean; one host's detail comes from `/host?host=`.
//! - `/api/v1/openapi.json` (no token needed) describes all of it.
//!
//! Nothing here runs commands on a host: Fleetboard's clients have no write routes at all.

use std::collections::HashMap;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use fleetboard_proto::Snapshot;
use serde::Deserialize;
use serde_json::{json, Value};

use super::errors::ApiError;
use super::hosts::{add_host, change_host, remove_host, HostPatch};
use super::AppState;
use crate::db::{ApiCall, RollupPoint};
use crate::poller::HostStatus;
use crate::rollup::{DAY, HOUR};
use crate::thresholds::{Thresholds, RANGES};
use crate::time::iso;
use crate::tokens::{self, Scope};

/// The OpenAPI 3 description, written by hand next to the code it describes.
pub const OPENAPI: &str = include_str!("openapi.json");

/// Who is calling, put on the request by [`auth`] for the handlers.
#[derive(Clone, Debug)]
pub struct Caller {
    pub name: String,   // the token's name
    pub scopes: String, // "read" or "read,act"
}

impl Caller {
    /// The audit log's "who" for anything this caller does.
    pub fn who(&self) -> String {
        format!("Mnemerynne/Claude (token {})", self.name)
    }
}

/// The routes, nested at `/api/v1` by `api::router`.
pub fn router(state: AppState) -> Router<AppState> {
    let authed = Router::new()
        // ------------------------------------------------------------ reads
        .route("/whoami", get(whoami))
        .route("/summary", get(summary))
        .route("/hosts", get(hosts).post(act_add_host))
        .route("/host", get(host_detail))
        .route("/over", get(over))
        .route("/disks/forecast", get(forecast))
        .route("/history", get(history))
        .route("/clients", get(clients))
        .route("/activity", get(activity))
        .route("/thresholds", get(thresholds))
        // ---------------------------------------------------------- actions
        .route("/hosts/{id}/rename", post(act_rename))
        .route("/hosts/{id}/pause", post(act_pause))
        .route("/hosts/{id}/resume", post(act_resume))
        .route("/hosts/{id}/remove", post(act_remove))
        .route("/thresholds/{name}", post(act_set_threshold))
        .layer(middleware::from_fn_with_state(state, auth)); // every route above needs a token
    Router::new()
        .route("/openapi.json", get(openapi))
        .merge(authed)
}

/// `GET /api/v1/openapi.json`: the description, for Mnemerynne's "import from OpenAPI".
async fn openapi() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        OPENAPI.to_string(),
    )
        .into_response()
}

// =============================================================== auth + call log

/// Check the bearer token, put a [`Caller`] on the request, and log the call whatever happens.
async fn auth(State(st): State<AppState>, mut req: Request<Body>, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().to_string();
    // The nest strips "/api/v1"; OriginalUri still has the whole path for the log.
    let uri = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|o| o.0.clone())
        .unwrap_or_else(|| req.uri().clone());
    let path: String = uri
        .path_and_query()
        .map(|p| p.as_str().chars().take(500).collect()) // long query strings are cut, not refused
        .unwrap_or_default();
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let found = match tokens::from_header(header) {
        Some(token) => st.db.token_by_hash(&tokens::hash(token)).ok().flatten(), // hash, then look up
        None => None,
    };
    let (res, token_name) = match found {
        Some(t) if t.revoked_at.is_none() => {
            let _ = st.db.touch_token(t.id, crate::now_unix()); // "last used" for `token list`
            let caller = Caller {
                name: t.name.clone(),
                scopes: t.scopes,
            };
            // Every route that isn't a GET is an action: a read token is refused here, before the
            // body is even parsed (the handlers check again).
            let res = if req.method() != axum::http::Method::GET
                && !tokens::grants(&caller.scopes, Scope::Act)
            {
                let target = path.split('?').next().unwrap_or("").to_string(); // e.g. /api/v1/hosts/3/pause
                require_act(&st, &caller, &method, &target)
                    .err()
                    .unwrap_or_else(|| ApiError::forbidden("This token may only read."))
                    .into_response()
            } else {
                req.extensions_mut().insert(caller);
                next.run(req).await
            };
            (res, t.name)
        }
        Some(t) => (
            unauthorized(
                "This token was revoked. Make a new one with `fleetboard-server token add`.",
            ),
            format!("{} (revoked)", t.name),
        ),
        None => (
            unauthorized("A Fleetboard service token is needed: Authorization: Bearer fbt_…"),
            "-".into(),
        ),
    };
    let call = ApiCall {
        ts: crate::now_unix(),
        token: token_name,
        method,
        path,
        status: res.status().as_u16(),
        ms: started.elapsed().as_millis() as u64,
    };
    if let Err(e) = st.db.log_call(&call) {
        tracing::warn!("couldn't log an API call: {e}");
    }
    res
}

/// A 401 with the `WWW-Authenticate` header clients expect.
fn unauthorized(msg: &str) -> Response {
    let mut res = ApiError(StatusCode::UNAUTHORIZED, msg.into()).into_response();
    res.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"fleetboard\""),
    );
    res
}

/// Refuse an action to a token without the `act` scope, and audit the refusal.
fn require_act(st: &AppState, caller: &Caller, action: &str, target: &str) -> Result<(), ApiError> {
    if tokens::grants(&caller.scopes, Scope::Act) {
        return Ok(());
    }
    st.db.audit(
        crate::now_unix(),
        &caller.who(),
        "api.denied",
        target,
        &format!("{action} refused: the token may only read"),
    )?;
    Err(ApiError::forbidden(
        "This token may only read. Changes need a token made with --scope act.",
    ))
}

/// The reason every action carries into the audit log: 3-500 printable characters.
fn clean_reason(reason: &str) -> Result<String, ApiError> {
    let r = reason.trim();
    if r.chars().count() < 3 || r.chars().count() > 500 || r.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad(
            "Say why in `reason` (3-500 printable characters); it goes in the audit log.",
        ));
    }
    Ok(r.to_string())
}

// =============================================================== shared helpers

/// One decimal place, for lean answers.
fn r1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn pct(used: u64, total: u64) -> Option<f64> {
    (total > 0).then(|| r1(used as f64 * 100.0 / total as f64))
}

/// up, down, paused or waiting (just added, not asked yet).
fn status_word(h: &HostStatus) -> &'static str {
    if !h.live.enabled {
        "paused"
    } else {
        match h.live.reachable {
            Some(true) => "up",
            Some(false) => "down",
            None => "waiting",
        }
    }
}

/// When the host last answered: this run's memory, else the newest stored sample.
fn last_seen(st: &AppState, h: &HostStatus) -> Option<u64> {
    h.last_ok_at
        .or_else(|| st.db.last_sample_ts(h.live.id).ok().flatten())
}

/// The fullest disk as (mount, used %).
fn fullest_disk(snap: &Snapshot) -> Option<(String, f64)> {
    snap.disks
        .iter()
        .filter_map(|d| pct(d.used_bytes, d.total_bytes).map(|p| (d.mount.clone(), p)))
        .max_by(|a, b| a.1.total_cmp(&b.1))
}

/// The hottest sensor or GPU as (label, °C).
fn hottest(snap: &Snapshot) -> Option<(String, f64)> {
    crate::wazuh::readings(snap)
        .into_iter()
        .map(|r| (r.sensor, r1(f64::from(r.celsius))))
        .max_by(|a, b| a.1.total_cmp(&b.1))
}

fn mem_pct(snap: &Snapshot) -> Option<f64> {
    pct(snap.memory.used_bytes, snap.memory.total_bytes)
}

/// Find a host by id, name or hostname (any case).
fn find_host(st: &AppState, key: &str) -> Result<HostStatus, ApiError> {
    let key = key.trim();
    let all = st.poller.statuses();
    let id = key.parse::<i64>().ok();
    all.iter()
        .find(|h| Some(h.live.id) == id)
        .or_else(|| all.iter().find(|h| h.live.name.eq_ignore_ascii_case(key)))
        .or_else(|| {
            all.iter().find(|h| {
                h.live
                    .snapshot
                    .as_ref()
                    .is_some_and(|s| s.host.hostname.eq_ignore_ascii_case(key))
            })
        })
        .cloned()
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "No host {key:?}. Use an id, name or hostname from Hosts."
            ))
        })
}

/// What's wrong with a host right now, in words, against the thresholds.
fn issues(h: &HostStatus, th: &Thresholds, age_s: Option<u64>) -> Vec<String> {
    let mut out = Vec::new();
    match status_word(h) {
        "down" => out.push(format!("not answering: {}", h.live.error)),
        "paused" => out.push("monitoring is paused".into()),
        _ => {}
    }
    if h.live.enabled && age_s.is_none_or(|a| a > u64::from(th.offline_minutes) * 60) {
        out.push(match age_s {
            Some(a) => format!("silent for {} min", a / 60),
            None => "never answered".into(),
        });
    }
    if let Some(s) = &h.live.snapshot {
        for d in &s.disks {
            if let Some(p) = pct(d.used_bytes, d.total_bytes) {
                if p >= f64::from(th.disk_pct) {
                    out.push(format!("disk {} {p}% full", d.mount));
                }
            }
        }
        if let Some(m) = mem_pct(s).filter(|m| *m >= f64::from(th.mem_pct)) {
            out.push(format!("memory {m}% used"));
        }
        for r in crate::wazuh::readings(s) {
            if f64::from(r.celsius) >= f64::from(th.temp_c) {
                out.push(format!("{} at {} C", r.sensor, r1(f64::from(r.celsius))));
            }
        }
    }
    out
}

/// One lean row per host: status, freshness, client and the headline numbers.
fn host_row(st: &AppState, h: &HostStatus, th: &Thresholds, now: u64) -> Value {
    let seen = last_seen(st, h);
    let age = seen.map(|t| now.saturating_sub(t));
    let snap = h.live.snapshot.as_ref();
    let silent = h.live.enabled && age.is_none_or(|a| a > u64::from(th.offline_minutes) * 60);
    json!({
        "id": h.live.id,
        "name": h.live.name,
        "address": h.live.address,
        "status": status_word(h),
        "silent": silent,
        "error": (!h.live.error.is_empty()).then(|| h.live.error.clone()),
        "last_seen": seen.map(iso),
        "data_age_s": age,
        "hostname": snap.map(|s| s.host.hostname.clone()),
        "os": snap.map(|s| s.host.os.clone()),
        "client_version": snap.map(|s| s.host.agent.clone()),
        "schema": snap.map(|s| s.schema),
        "uptime_h": snap.map(|s| r1(s.host.uptime_s as f64 / 3600.0)),
        "cpu_pct": snap.map(|s| r1(f64::from(s.cpu.percent))),
        "mem_pct": snap.and_then(mem_pct),
        "fullest_disk": snap.and_then(fullest_disk).map(|d| d.0),
        "fullest_disk_pct": snap.and_then(fullest_disk).map(|d| d.1),
        "hottest_c": snap.and_then(hottest).map(|t| t.1),
        "issues": issues(h, th, age).len(),
    })
}

// ======================================================================= reads

/// `GET /whoami`: the token's name and what it may do (an admin's first *Test*).
async fn whoami(Extension(caller): Extension<Caller>) -> Json<Value> {
    Json(json!({
        "token": caller.name,
        "read": tokens::grants(&caller.scopes, Scope::Read),
        "act": tokens::grants(&caller.scopes, Scope::Act),
        "server_version": crate::VERSION,
    }))
}

/// `GET /summary`: the morning brief in one call.
async fn summary(State(st): State<AppState>) -> Json<Value> {
    let now = crate::now_unix();
    let th = st.poller.thresholds();
    let all = st.poller.statuses();
    let count = |w: &str| all.iter().filter(|h| status_word(h) == w).count();
    let mut silent = 0;
    let mut with_issues = Vec::new();
    for h in &all {
        let age = last_seen(&st, h).map(|t| now.saturating_sub(t));
        if h.live.enabled && age.is_none_or(|a| a > u64::from(th.offline_minutes) * 60) {
            silent += 1;
        }
        let list = issues(h, &th, age);
        if !list.is_empty() {
            with_issues.push(json!({"host": h.live.name, "issues": list.join("; ")}));
        }
    }
    let mut busiest: Vec<Value> = all
        .iter()
        .filter_map(|h| {
            h.live.snapshot.as_ref().map(|s| {
                json!({"host": h.live.name, "cpu_pct": r1(f64::from(s.cpu.percent)), "mem_pct": mem_pct(s)})
            })
        })
        .collect();
    busiest.sort_by(|a, b| {
        b["cpu_pct"]
            .as_f64()
            .unwrap_or(0.0)
            .total_cmp(&a["cpu_pct"].as_f64().unwrap_or(0.0))
    });
    busiest.truncate(5);
    let mut fullest: Vec<(String, String, f64)> = all
        .iter()
        .filter_map(|h| h.live.snapshot.as_ref().map(|s| (h, s)))
        .flat_map(|(h, s)| {
            s.disks.iter().filter_map(|d| {
                pct(d.used_bytes, d.total_bytes).map(|p| (h.live.name.clone(), d.mount.clone(), p))
            })
        })
        .collect();
    fullest.sort_by(|a, b| b.2.total_cmp(&a.2));
    fullest.truncate(5);
    Json(json!({
        "generated_at": iso(now),
        "hosts": all.len(),
        "up": count("up"),
        "down": count("down"),
        "paused": count("paused"),
        "waiting": count("waiting"),
        "silent": silent,
        "busiest": busiest,
        "fullest_disks": fullest.iter().map(|(h, m, p)| json!({"host": h, "mount": m, "used_pct": p})).collect::<Vec<_>>(),
        "issues": with_issues,
        "thresholds": th,
    }))
}

#[derive(Deserialize)]
struct HostsQuery {
    status: Option<String>,      // all, up, down, paused, silent, issues
    silent_minutes: Option<u32>, // overrides offline_minutes for "silent"
}

/// `GET /hosts`: one lean row per host. `status=silent` lists the hosts that went quiet.
async fn hosts(
    State(st): State<AppState>,
    Query(q): Query<HostsQuery>,
) -> Result<Json<Value>, ApiError> {
    let now = crate::now_unix();
    let mut th = st.poller.thresholds();
    if let Some(m) = q.silent_minutes {
        th.offline_minutes = m.clamp(1, 7 * 24 * 60);
    }
    let want = q.status.as_deref().unwrap_or("all").to_ascii_lowercase();
    if !["all", "up", "down", "paused", "waiting", "silent", "issues"].contains(&want.as_str()) {
        return Err(ApiError::bad(
            "status is one of all, up, down, paused, waiting, silent or issues.",
        ));
    }
    let rows: Vec<Value> = st
        .poller
        .statuses()
        .iter()
        .map(|h| (status_word(h), host_row(&st, h, &th, now)))
        .filter(|(word, row)| match want.as_str() {
            "all" => true,
            "silent" => row["silent"] == json!(true),
            "issues" => row["issues"].as_u64().unwrap_or(0) > 0,
            w => *word == w,
        })
        .map(|(_, row)| row)
        .collect();
    Ok(Json(json!({"total": rows.len(), "rows": rows})))
}

#[derive(Deserialize)]
struct HostQuery {
    host: String,
}

/// `GET /host?host=`: one host in full: facts, CPU, memory, each disk, GPU, sensor and the
/// busiest network interfaces, plus what's wrong with it right now.
async fn host_detail(
    State(st): State<AppState>,
    Query(q): Query<HostQuery>,
) -> Result<Json<Value>, ApiError> {
    let now = crate::now_unix();
    let th = st.poller.thresholds();
    let h = find_host(&st, &q.host)?;
    let seen = last_seen(&st, &h);
    let age = seen.map(|t| now.saturating_sub(t));
    let mut out = json!({
        "id": h.live.id,
        "name": h.live.name,
        "address": h.live.address,
        "status": status_word(&h),
        "error": (!h.live.error.is_empty()).then(|| h.live.error.clone()),
        "last_seen": seen.map(iso),
        "data_age_s": age,
        "latency_ms": h.live.latency_ms,
        "down_since": h.down_since.map(iso),
        "issues": issues(&h, &th, age),
    });
    if let Some(s) = &h.live.snapshot {
        let mut nets: Vec<_> = s.network.iter().collect();
        nets.sort_by_key(|n| std::cmp::Reverse(n.rx_bps + n.tx_bps));
        let extra = json!({
            "hostname": s.host.hostname,
            "os": s.host.os,
            "kernel": s.host.kernel,
            "arch": s.host.arch,
            "uptime_h": r1(s.host.uptime_s as f64 / 3600.0),
            "client_version": s.host.agent,
            "schema": s.schema,
            "listen": s.host.listen,
            "binary_sha256": s.host.binary_sha256,
            "cpu_model": s.cpu.model,
            "cpu_cores": s.cpu.cores,
            "cpu_pct": r1(f64::from(s.cpu.percent)),
            "load1": s.cpu.load1, "load5": s.cpu.load5, "load15": s.cpu.load15,
            "mem_used_bytes": s.memory.used_bytes,
            "mem_total_bytes": s.memory.total_bytes,
            "mem_available_bytes": s.memory.available_bytes,
            "mem_pct": mem_pct(s),
            "swap_used_bytes": s.memory.swap_used_bytes,
            "swap_total_bytes": s.memory.swap_total_bytes,
            "disks": s.disks.iter().map(|d| json!({
                "mount": d.mount, "fs": d.fs, "used_bytes": d.used_bytes, "total_bytes": d.total_bytes,
                "free_bytes": d.total_bytes.saturating_sub(d.used_bytes), "used_pct": pct(d.used_bytes, d.total_bytes),
            })).collect::<Vec<_>>(),
            "gpus": s.gpus.iter().map(|g| json!({
                "index": g.index, "name": g.name, "util_pct": g.util_percent, "temp_c": g.temp_c,
                "vram_used_bytes": g.vram_used_bytes, "vram_total_bytes": g.vram_total_bytes, "power_w": g.power_w,
            })).collect::<Vec<_>>(),
            "temperatures": s.temperatures.iter().map(|t| json!({
                "sensor": t.label, "temp_c": r1(f64::from(t.celsius)), "max_c": t.max_c,
            })).collect::<Vec<_>>(),
            "network": nets.iter().take(8).map(|n| json!({
                "interface": n.name, "rx_bps": n.rx_bps, "tx_bps": n.tx_bps,
            })).collect::<Vec<_>>(),
        });
        if let (Value::Object(o), Value::Object(e)) = (&mut out, extra) {
            o.extend(e);
        }
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct OverQuery {
    disk_pct: Option<u32>,
    mem_pct: Option<u32>,
    temp_c: Option<u32>,
}

/// `GET /over`: everything over a limit right now: disks, memory, temperatures, and hosts silent
/// for longer than offline_minutes. Each limit defaults to the stored threshold.
async fn over(State(st): State<AppState>, Query(q): Query<OverQuery>) -> Json<Value> {
    let now = crate::now_unix();
    let th = st.poller.thresholds();
    let disk = f64::from(q.disk_pct.unwrap_or(th.disk_pct).min(100));
    let mem = f64::from(q.mem_pct.unwrap_or(th.mem_pct).min(100));
    let temp = f64::from(q.temp_c.unwrap_or(th.temp_c).min(200));
    let mut rows = Vec::new();
    for h in st.poller.statuses() {
        let age = last_seen(&st, &h).map(|t| now.saturating_sub(t));
        if h.live.enabled && age.is_none_or(|a| a > u64::from(th.offline_minutes) * 60) {
            rows.push(json!({"host": h.live.name, "kind": "offline", "item": h.live.error,
                             "value": age.map(|a| a / 60), "unit": "min", "limit": th.offline_minutes}));
        }
        let Some(s) = &h.live.snapshot else { continue };
        for d in &s.disks {
            if let Some(p) = pct(d.used_bytes, d.total_bytes).filter(|p| *p >= disk) {
                rows.push(json!({"host": h.live.name, "kind": "disk", "item": d.mount, "value": p, "unit": "pct", "limit": disk}));
            }
        }
        if let Some(m) = mem_pct(s).filter(|m| *m >= mem) {
            rows.push(json!({"host": h.live.name, "kind": "memory", "item": "RAM", "value": m, "unit": "pct", "limit": mem}));
        }
        for r in crate::wazuh::readings(s) {
            let c = r1(f64::from(r.celsius));
            if c >= temp {
                rows.push(json!({"host": h.live.name, "kind": "temperature", "item": r.sensor, "value": c, "unit": "c", "limit": temp}));
            }
        }
    }
    Json(
        json!({"total": rows.len(), "limits": {"disk_pct": disk, "mem_pct": mem, "temp_c": temp,
                "offline_minutes": th.offline_minutes}, "rows": rows}),
    )
}

#[derive(Deserialize)]
struct ForecastQuery {
    host: Option<String>,
    days: Option<u32>,        // how far back the trend looks (default 14)
    within_days: Option<u32>, // only disks expected to fill within this many days
}

/// Least-squares slope of (x, y) points; None with fewer than two distinct x.
pub fn slope(points: &[(f64, f64)]) -> Option<f64> {
    if points.len() < 2 {
        return None;
    }
    let n = points.len() as f64;
    let (mx, my) = points
        .iter()
        .fold((0.0, 0.0), |(a, b), (x, y)| (a + x / n, b + y / n));
    let (mut cov, mut var) = (0.0, 0.0);
    for (x, y) in points {
        cov += (x - mx) * (y - my);
        var += (x - mx) * (x - mx);
    }
    (var > 0.0).then(|| cov / var)
}

/// Growth in bytes per day of one disk, and what it's based on: the daily averages if there are
/// at least three days, else the hourly averages (six hours or more), else nothing yet.
pub fn disk_growth(daily: &[RollupPoint], hourly: &[RollupPoint]) -> (Option<f64>, String) {
    let per_day = |pts: &[RollupPoint]| {
        let xy: Vec<(f64, f64)> = pts
            .iter()
            .map(|p| (p.start as f64 / DAY as f64, p.avg))
            .collect();
        slope(&xy)
    };
    if daily.len() >= 3 {
        return (
            per_day(daily),
            format!("daily averages, {} days", daily.len()),
        );
    }
    if hourly.len() >= 6 {
        return (
            per_day(hourly),
            format!("hourly averages, {} hours", hourly.len()),
        );
    }
    (None, "not enough history yet (needs 6 hours)".into())
}

/// `GET /disks/forecast`: per disk, how full it is, how fast it grows, and "full in about N days".
async fn forecast(
    State(st): State<AppState>,
    Query(q): Query<ForecastQuery>,
) -> Result<Json<Value>, ApiError> {
    let now = crate::now_unix();
    let days = q.days.unwrap_or(14).clamp(2, 90);
    let hosts = match &q.host {
        Some(key) if !key.trim().is_empty() => vec![find_host(&st, key)?],
        _ => st.poller.statuses(),
    };
    let mut rows = Vec::new();
    for h in hosts {
        let Some(s) = &h.live.snapshot else { continue };
        for d in s.disks.iter().filter(|d| d.total_bytes > 0) {
            let metric = format!("disk:{}", d.mount);
            let daily: Vec<RollupPoint> = st
                .db
                .rollup_series(
                    h.live.id,
                    DAY,
                    &metric,
                    now.saturating_sub(u64::from(days) * DAY),
                )?
                .into_iter()
                .filter(|p| p.metric == metric)
                .collect();
            let hourly: Vec<RollupPoint> = st
                .db
                .rollup_series(h.live.id, HOUR, &metric, now.saturating_sub(7 * DAY))?
                .into_iter()
                .filter(|p| p.metric == metric)
                .collect();
            let (growth, basis) = disk_growth(&daily, &hourly);
            let free = d.total_bytes.saturating_sub(d.used_bytes) as f64;
            let full_in = growth.filter(|g| *g > 0.0).map(|g| r1(free / g));
            if let (Some(limit), Some(f)) = (q.within_days, full_in) {
                if f > f64::from(limit) {
                    continue;
                }
            } else if q.within_days.is_some() {
                continue; // not growing: not filling within any limit
            }
            rows.push(json!({
                "host": h.live.name, "mount": d.mount,
                "used_pct": pct(d.used_bytes, d.total_bytes),
                "used_bytes": d.used_bytes, "total_bytes": d.total_bytes, "free_bytes": free as u64,
                "growth_bytes_per_day": growth.map(|g| g.round() as i64),
                "full_in_days": full_in,
                "full_by": full_in.map(|f| iso(now + (f * DAY as f64) as u64)),
                "basis": basis,
            }));
        }
    }
    rows.sort_by(|a, b| {
        let key = |v: &Value| v["full_in_days"].as_f64().unwrap_or(f64::INFINITY);
        key(a).total_cmp(&key(b))
    });
    Ok(Json(
        json!({"total": rows.len(), "trend_days": days, "rows": rows}),
    ))
}

#[derive(Deserialize)]
struct HistoryQuery {
    host: String,
    metric: String,
    hours: Option<u32>,
    days: Option<u32>,
    interval: Option<String>, // auto, 10s, 1m, 5m, 15m, 1h, 6h, 1d
}

/// Seconds of an interval word; "auto" (or nothing) is None.
fn interval_seconds(word: Option<&str>) -> Result<Option<u64>, ApiError> {
    Ok(
        match word.unwrap_or("auto").trim().to_ascii_lowercase().as_str() {
            "" | "auto" => None,
            "10s" => Some(10),
            "1m" => Some(60),
            "5m" => Some(300),
            "15m" => Some(900),
            "1h" => Some(HOUR),
            "6h" => Some(6 * HOUR),
            "1d" => Some(DAY),
            _ => {
                return Err(ApiError::bad(
                    "interval is one of auto, 10s, 1m, 5m, 15m, 1h, 6h or 1d.",
                ))
            }
        },
    )
}

/// A name reduced to letters and digits in lower case, so "C" finds "C:\" and "ethernet 2" finds
/// "Ethernet 2" (Mnemerynne's parameters can't carry `\` or brackets).
fn plain(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// What a stored rollup metric is about: "disk:C:\" → ("disk", "C:\"), "net:eth0:rx" → ("net", "eth0").
fn subject(metric: &str) -> (&str, &str) {
    let (family, rest) = metric.split_once(':').unwrap_or((metric, ""));
    let rest = match family {
        "net" => rest.rsplit_once(':').map_or(rest, |(s, _)| s), // drop :rx / :tx
        "gpu" => rest.split(':').next().unwrap_or(rest),         // drop :temp / :vram
        _ => rest,
    };
    (family, rest)
}

/// The stored metric names a request means: "cpu" → ["cpu"], "disk:C" → ["disk:C:\"],
/// "net:eth0" → ["net:eth0:rx", "net:eth0:tx"], "disk" → every disk.
pub fn resolve_metric(asked: &str, stored: &[String]) -> Vec<String> {
    let asked = asked.trim();
    if stored.iter().any(|m| m == asked) && !asked.starts_with("net:") && !asked.starts_with("gpu:")
    {
        return vec![asked.to_string()]; // exact (cpu, mem, disk:/)
    }
    let (family, want) = asked.split_once(':').unwrap_or((asked, ""));
    let family = family.to_ascii_lowercase();
    stored
        .iter()
        .filter(|m| {
            let (f, s) = subject(m);
            f == family && (want.is_empty() || plain(s) == plain(want) || s == want)
        })
        .cloned()
        .collect()
}

/// The unit of a stored metric, for the rows.
fn unit_of(metric: &str) -> &'static str {
    match subject(metric).0 {
        "cpu" | "mem" => "pct",
        "load" => "load",
        "temp" => "c",
        "disk" => "bytes",
        "net" => "bytes_per_s",
        "gpu" if metric.ends_with(":temp") => "c",
        "gpu" if metric.ends_with(":vram") => "bytes",
        "gpu" => "pct",
        _ => "",
    }
}

/// `GET /history`: one metric of one host over hours (10-second data for cpu/mem/load up to 24 h,
/// hourly rollups up to 7 days) or days (daily rollups up to 90 days), as min/avg/max per interval.
async fn history(
    State(st): State<AppState>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Value>, ApiError> {
    let now = crate::now_unix();
    let h = find_host(&st, &q.host)?;
    let id = h.live.id;
    let asked = q.metric.trim().to_string();
    let family = asked.split(':').next().unwrap_or("").to_ascii_lowercase();
    if !["cpu", "mem", "load", "temp", "disk", "net", "gpu"].contains(&family.as_str()) {
        return Err(ApiError::bad(
            "metric is cpu, mem, load, temp, disk[:<mount>], net[:<interface>] or gpu[:<n>].",
        ));
    }
    let interval = interval_seconds(q.interval.as_deref())?;
    let (span, from) = match (q.days, q.hours) {
        (Some(d), _) => (DAY, now.saturating_sub(u64::from(d.clamp(1, 90)) * DAY)),
        (None, hrs) => {
            let hrs = u64::from(hrs.unwrap_or(24).clamp(1, 168));
            let from = now.saturating_sub(hrs * HOUR);
            let fine = ["cpu", "mem", "load"].contains(&asked.as_str())
                && hrs <= 24
                && interval.is_none_or(|i| i < HOUR);
            if fine {
                // 10-second rows: at most ~120 points unless an interval was asked for.
                let step = interval.unwrap_or_else(|| {
                    let want = hrs * HOUR / 120;
                    [10, 60, 300, 900, HOUR]
                        .into_iter()
                        .find(|s| *s >= want)
                        .unwrap_or(HOUR)
                });
                let pts = st.db.sample_series(id, &asked, from, step)?;
                let rows: Vec<Value> = pts
                    .iter()
                    .map(|(ts, mn, avg, mx)| json!({"series": asked, "at": iso(*ts), "min": r1(*mn), "avg": r1(*avg), "max": r1(*mx), "unit": unit_of(&asked)}))
                    .collect();
                return Ok(Json(
                    json!({"host": h.live.name, "metric": asked, "from": iso(from), "to": iso(now),
                                      "interval_s": step, "source": "10-second samples", "total": rows.len(), "rows": rows}),
                ));
            }
            (HOUR, from)
        }
    };
    let stored = st.db.rollup_metrics(id)?;
    let names = resolve_metric(&asked, &stored);
    if names.is_empty() {
        let mut known: Vec<String> = stored
            .iter()
            .filter(|m| subject(m).0 == family)
            .map(|m| m.split(':').take(2).collect::<Vec<_>>().join(":"))
            .collect();
        known.dedup();
        return Err(ApiError::not_found(format!(
            "No {asked:?} history for {} yet. Known: {}.",
            h.live.name,
            if known.is_empty() {
                "none".into()
            } else {
                known.join(", ")
            }
        )));
    }
    let step = interval.unwrap_or(span).max(span); // rollups can't be finer than their span
    let mut rows = Vec::new();
    for name in &names {
        let pts = st.db.rollup_series(id, span, name, from)?;
        // Regroup into `step` buckets: min of mins, max of maxes, mean of the averages.
        let mut groups: Vec<(u64, f64, f64, f64, usize, Option<f64>)> = Vec::new();
        for p in pts.iter().filter(|p| &p.metric == name) {
            let b = p.start - p.start % step;
            match groups.last_mut() {
                Some(g) if g.0 == b => {
                    g.1 = g.1.min(p.min);
                    g.2 += p.avg;
                    g.3 = g.3.max(p.max);
                    g.4 += 1;
                    g.5 = p.cap.or(g.5);
                }
                _ => groups.push((b, p.min, p.avg, p.max, 1, p.cap)),
            }
        }
        for (b, mn, sum, mx, n, cap) in groups {
            let avg = sum / n as f64;
            let mut row = json!({"series": name, "at": iso(b), "min": r1(mn), "avg": r1(avg), "max": r1(mx), "unit": unit_of(name)});
            if let Some(c) = cap.filter(|c| *c > 0.0) {
                row["used_pct"] = json!(r1(avg * 100.0 / c));
                row["total_bytes"] = json!(c as u64);
            }
            rows.push(row);
        }
    }
    Ok(Json(
        json!({"host": h.live.name, "metric": names, "from": iso(from), "to": iso(now), "interval_s": step,
                   "source": if span == DAY { "daily rollups" } else { "hourly rollups" },
                   "total": rows.len(), "rows": rows}),
    ))
}

#[derive(Deserialize)]
struct ClientsQuery {
    flagged_only: Option<bool>,
}

/// Whether a `bind` listens on every address.
fn listens_everywhere(listen: &str) -> bool {
    listen.starts_with("0.0.0.0:") || listen.starts_with("[::]:") || listen.starts_with(":::")
}

/// `GET /clients`: the client audit: version, schema, where each client listens and its binary's
/// SHA-256, with flags for clients listening on every address, builds that differ from the other
/// hosts on the same version and platform, and clients older than the newest one.
async fn clients(State(st): State<AppState>, Query(q): Query<ClientsQuery>) -> Json<Value> {
    let all = st.poller.statuses();
    let facts: Vec<(&HostStatus, &Snapshot)> = all
        .iter()
        .filter_map(|h| h.live.snapshot.as_ref().map(|s| (h, s)))
        .collect();
    let platform = |s: &Snapshot| {
        let os = if s.host.os.to_lowercase().contains("windows") {
            "windows"
        } else {
            "unix"
        };
        format!("{} {} {}", s.host.agent, os, s.host.arch)
    };
    // The most common hash per (version, platform): what "expected" means without a release list.
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for (_, s) in &facts {
        if let Some(sha) = &s.host.binary_sha256 {
            *counts.entry((platform(s), sha.clone())).or_default() += 1;
        }
    }
    let usual = |p: &str| {
        let mut best: Option<(&String, usize, usize)> = None; // (sha, count, how many hashes share the platform)
        let mut kinds = 0;
        for ((plat, sha), n) in &counts {
            if plat == p {
                kinds += 1;
                if best.is_none_or(|b| *n > b.1) {
                    best = Some((sha, *n, 0));
                }
            }
        }
        best.map(|b| (b.0.clone(), b.1, kinds))
    };
    let newest = facts
        .iter()
        .map(|(_, s)| s.host.agent.clone())
        .max_by(|a, b| version_key(a).cmp(&version_key(b)));
    let mut rows = Vec::new();
    for h in &all {
        let s = h.live.snapshot.as_ref();
        let mut flags = Vec::new();
        match s {
            None => flags.push("never answered: nothing known about its client".to_string()),
            Some(s) => {
                match &s.host.listen {
                    Some(l) if listens_everywhere(l) => flags.push(format!(
                        "listens on every address ({l}): check its firewall lets only the Mnemerynne box reach the port"
                    )),
                    Some(_) => {}
                    None => flags.push("doesn't report where it listens (client older than this server)".into()),
                }
                match (&s.host.binary_sha256, usual(&platform(s))) {
                    (None, _) => flags.push(
                        "doesn't report its binary's SHA-256 (client older than this server)"
                            .into(),
                    ),
                    (Some(sha), Some((common, n, kinds))) if kinds > 1 && *sha != common => flags
                        .push(format!(
                            "binary differs from the {n} other host(s) on {} {}",
                            s.host.agent, s.host.arch
                        )),
                    _ => {}
                }
                if newest
                    .as_ref()
                    .is_some_and(|n| version_key(n) > version_key(&s.host.agent))
                {
                    flags.push(format!(
                        "older client ({}) than the newest here ({})",
                        s.host.agent,
                        newest.clone().unwrap_or_default()
                    ));
                }
            }
        }
        if q.flagged_only == Some(true) && flags.is_empty() {
            continue;
        }
        rows.push(json!({
            "host": h.live.name,
            "status": status_word(h),
            "client_version": s.map(|s| s.host.agent.clone()),
            "schema": s.map(|s| s.schema),
            "os": s.map(|s| s.host.os.clone()),
            "arch": s.map(|s| s.host.arch.clone()),
            "listen": s.and_then(|s| s.host.listen.clone()),
            "binary_sha256": s.and_then(|s| s.host.binary_sha256.clone()),
            "flags": flags.join("; "),
        }));
    }
    Json(json!({"total": rows.len(), "newest_client": newest, "rows": rows}))
}

/// "0.10.2" sorts after "0.9.9".
fn version_key(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter_map(|p| p.parse().ok())
        .collect()
}

#[derive(Deserialize)]
struct ActivityQuery {
    limit: Option<u32>,
    host: Option<String>,
}

/// `GET /activity`: the audit log, newest first: who added, changed, paused or removed what,
/// and every change made through this API with its reason.
async fn activity(
    State(st): State<AppState>,
    Query(q): Query<ActivityQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let host = q.host.as_deref().map(str::trim).filter(|h| !h.is_empty());
    let rows: Vec<Value> = st
        .db
        .recent_audit(limit, host)?
        .into_iter()
        .map(|r| json!({"at": iso(r.ts), "who": r.who, "action": r.action, "host": r.target, "detail": r.detail}))
        .collect();
    Ok(Json(json!({"total": rows.len(), "rows": rows})))
}

/// `GET /thresholds`: the limits in use, with their ranges and defaults.
async fn thresholds(State(st): State<AppState>) -> Json<Value> {
    let cur = serde_json::to_value(st.poller.thresholds()).unwrap_or_default();
    let def = serde_json::to_value(Thresholds::default()).unwrap_or_default();
    let rows: Vec<Value> = RANGES
        .iter()
        .map(|(n, lo, hi)| json!({"name": n, "value": cur[n], "default": def[n], "min": lo, "max": hi}))
        .collect();
    Json(json!({"total": rows.len(), "rows": rows}))
}

// ===================================================================== actions

#[derive(Deserialize)]
struct Reason {
    reason: String,
}

#[derive(Deserialize)]
struct AddBody {
    name: String,
    address: String,
    reason: String,
}

#[derive(Deserialize)]
struct RenameBody {
    name: String,
    reason: String,
}

#[derive(Deserialize)]
struct ThresholdBody {
    value: u32,
    reason: String,
}

/// The audit's name for a host id, for refusals of hosts that exist.
fn host_name(st: &AppState, id: i64) -> Result<String, ApiError> {
    Ok(st
        .db
        .get_host(id)?
        .ok_or_else(|| ApiError::not_found("No such host."))?
        .name)
}

/// `POST /hosts`: add a host (checked first: it must answer with the shared token).
async fn act_add_host(
    State(st): State<AppState>,
    Extension(caller): Extension<Caller>,
    Json(b): Json<AddBody>,
) -> Result<impl IntoResponse, ApiError> {
    require_act(&st, &caller, "host.add", b.name.trim())?;
    let reason = clean_reason(&b.reason)?;
    let row = add_host(&st, &caller.who(), &b.name, &b.address, &reason).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"done": "added", "host": row})),
    ))
}

/// `POST /hosts/{id}/rename`.
async fn act_rename(
    State(st): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
    Json(b): Json<RenameBody>,
) -> Result<Json<Value>, ApiError> {
    let name = host_name(&st, id)?;
    require_act(&st, &caller, "host.rename", &name)?;
    let reason = clean_reason(&b.reason)?;
    let patch = HostPatch {
        name: Some(b.name),
        ..Default::default()
    };
    let row = change_host(&st, id, &caller.who(), &patch, &reason).await?;
    Ok(Json(json!({"done": "renamed", "was": name, "host": row})))
}

/// `POST /hosts/{id}/pause`: stop polling (and alerting on) a host; its history stays.
async fn act_pause(
    State(st): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
    Json(b): Json<Reason>,
) -> Result<Json<Value>, ApiError> {
    set_enabled(st, caller, id, b, false).await
}

/// `POST /hosts/{id}/resume`: poll a paused host again (it must answer first).
async fn act_resume(
    State(st): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
    Json(b): Json<Reason>,
) -> Result<Json<Value>, ApiError> {
    set_enabled(st, caller, id, b, true).await
}

async fn set_enabled(
    st: AppState,
    caller: Caller,
    id: i64,
    b: Reason,
    enabled: bool,
) -> Result<Json<Value>, ApiError> {
    let host = st
        .db
        .get_host(id)?
        .ok_or_else(|| ApiError::not_found("No such host."))?;
    let action = if enabled { "host.resume" } else { "host.pause" };
    require_act(&st, &caller, action, &host.name)?;
    let reason = clean_reason(&b.reason)?;
    if host.enabled == enabled {
        return Err(ApiError::conflict(format!(
            "{} is already {}.",
            host.name,
            if enabled { "monitored" } else { "paused" }
        )));
    }
    let patch = HostPatch {
        enabled: Some(enabled),
        ..Default::default()
    };
    let row = change_host(&st, id, &caller.who(), &patch, &reason).await?;
    Ok(Json(
        json!({"done": if enabled { "resumed" } else { "paused" }, "host": row}),
    ))
}

/// `POST /hosts/{id}/remove`: remove a host and all its history. Irreversible.
async fn act_remove(
    State(st): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
    Json(b): Json<Reason>,
) -> Result<Json<Value>, ApiError> {
    let name = host_name(&st, id)?;
    require_act(&st, &caller, "host.remove", &name)?;
    let reason = clean_reason(&b.reason)?;
    let host = remove_host(&st, id, &caller.who(), &reason)?;
    Ok(Json(
        json!({"done": "removed", "host": host.name, "address": host.address}),
    ))
}

/// `POST /thresholds/{name}`: change one limit (disk_pct, disk_critical_pct, mem_pct, temp_c,
/// offline_minutes). Used from the next poll on by the audit operations and the Wazuh alerts.
async fn act_set_threshold(
    State(st): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path(name): Path<String>,
    Json(b): Json<ThresholdBody>,
) -> Result<Json<Value>, ApiError> {
    require_act(&st, &caller, "threshold.set", &name)?;
    let reason = clean_reason(&b.reason)?;
    let (old, next) = st
        .poller
        .thresholds()
        .with(&name, b.value)
        .map_err(ApiError::bad)?;
    Thresholds::save(&st.db, &name, b.value)?;
    st.poller.set_thresholds(next);
    st.db.audit(
        crate::now_unix(),
        &caller.who(),
        "threshold.set",
        &name,
        &format!("{name} {old} -> {}; reason: {reason}", b.value),
    )?;
    Ok(Json(
        json!({"done": "set", "name": name, "was": old, "now": b.value}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(metric: &str, start: u64, avg: f64) -> RollupPoint {
        RollupPoint {
            metric: metric.into(),
            start,
            min: avg,
            avg,
            max: avg,
            cap: Some(1000.0),
            first: avg,
            first_ts: start,
            last: avg,
            last_ts: start,
        }
    }

    #[test]
    fn a_steady_disk_grows_by_its_daily_step() {
        let daily: Vec<_> = (0..5)
            .map(|d| pt("disk:/", d * DAY, 100.0 + 10.0 * d as f64))
            .collect();
        let (g, basis) = disk_growth(&daily, &[]);
        assert!((g.unwrap() - 10.0).abs() < 1e-9);
        assert!(basis.starts_with("daily"));
        let hourly: Vec<_> = (0..6)
            .map(|h| pt("disk:/", h * HOUR, 100.0 + h as f64))
            .collect();
        let (g, basis) = disk_growth(&daily[..1], &hourly);
        assert!((g.unwrap() - 24.0).abs() < 1e-9); // 1 byte an hour = 24 a day
        assert!(basis.starts_with("hourly"));
        assert_eq!(disk_growth(&[], &hourly[..2]).0, None);
    }

    #[test]
    fn metric_names_resolve_without_backslashes_or_brackets() {
        let stored: Vec<String> = [
            "cpu",
            "disk:/",
            "disk:C:\\",
            "net:Ethernet (2):rx",
            "net:Ethernet (2):tx",
            "gpu:0",
            "gpu:0:temp",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(resolve_metric("cpu", &stored), vec!["cpu"]);
        assert_eq!(resolve_metric("disk:/", &stored), vec!["disk:/"]);
        assert_eq!(resolve_metric("disk:C", &stored), vec!["disk:C:\\"]);
        assert_eq!(resolve_metric("net:ethernet 2", &stored).len(), 2);
        assert_eq!(
            resolve_metric("gpu:0", &stored),
            vec!["gpu:0", "gpu:0:temp"]
        );
        assert_eq!(resolve_metric("disk", &stored).len(), 2);
        assert!(resolve_metric("disk:Z", &stored).is_empty());
        assert_eq!(unit_of("gpu:0:temp"), "c");
        assert_eq!(unit_of("net:eth0:rx"), "bytes_per_s");
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(version_key("0.10.0") > version_key("0.9.9"));
        assert!(listens_everywhere("0.0.0.0:9280") && listens_everywhere("[::]:9280"));
        assert!(!listens_everywhere("127.0.0.1:9280"));
    }
}
