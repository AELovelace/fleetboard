//! The `/api/v1` service API end to end, inside one process: a real client router on an ephemeral
//! port, a real Poller with an in-memory database, and the server's router driven with
//! `tower::ServiceExt::oneshot`. Covers the token checks, the reads, the audit trail of every
//! action and the refusals.

use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fleetboard_client::http::{router as client_router, AppState as ClientState};
use fleetboard_proto::{Cpu, Disk, HostFacts, Memory, Snapshot, SCHEMA};
use fleetboard_server::api::{router, AppState};
use fleetboard_server::db::Db;
use fleetboard_server::poller::Poller;
use fleetboard_server::rollup::{Acc, RollupRow, DAY};
use fleetboard_server::tokens;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

// Plainly fake secrets, so scanners don't take them for real ones.
const CLIENT_TOKEN: &str = "test-client-token-test-client-token";

/// A client that already has one snapshot (a 95%-full disk), on 127.0.0.1:<random>.
async fn start_client() -> String {
    let snap = Snapshot {
        schema: SCHEMA,
        taken_at: 1,
        host: HostFacts {
            hostname: "rsync-box".into(),
            os: "TestOS".into(),
            arch: "x86_64".into(),
            agent: "0.1.0".into(),
            listen: Some("0.0.0.0:9280".into()),
            binary_sha256: Some("ab".repeat(32)),
            ..Default::default()
        },
        cpu: Cpu {
            percent: 42.0,
            cores: 4,
            ..Default::default()
        },
        memory: Memory {
            used_bytes: 1,
            total_bytes: 2,
            ..Default::default()
        },
        disks: vec![Disk {
            mount: "/srv".into(),
            device: None,
            fs: "xfs".into(),
            used_bytes: 950,
            total_bytes: 1000,
        }],
        network: vec![],
        gpus: vec![],
        temperatures: vec![],
    };
    let state = ClientState {
        latest: Arc::new(RwLock::new(Some(snap))),
        token: CLIENT_TOKEN.into(),
        allowed_hosts: Arc::new(vec![]),
        hostname: "rsync-box".into(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, client_router(state)).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

struct Fixture {
    app: axum::Router,
    db: Db,
    host_id: i64,
    read: String, // a read-only token
    act: String,  // a read + act token
}

/// One host that answers, polled once, plus a read token and an act token.
async fn fixture() -> Fixture {
    let address = start_client().await;
    let db = Db::in_memory().unwrap();
    let host = db.insert_host("rsync-box", &address, 1).unwrap();
    let poller = Poller::new(db.clone(), CLIENT_TOKEN.into(), vec![host.clone()]);
    poller.poll_once().await;
    let (read, _) = tokens::create(&db, "mnemerynne-read", "read", 1).unwrap();
    let (act, _) = tokens::create(&db, "mnemerynne-act", "act", 1).unwrap();
    let app = router(AppState {
        db: db.clone(),
        poller,
        token_set: true,
    });
    Fixture {
        app,
        db,
        host_id: host.id,
        read,
        act,
    }
}

/// Send one request; returns the status and the JSON body (Null when it isn't JSON).
async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn missing_wrong_revoked_and_client_tokens_are_refused() {
    let f = fixture().await;
    let (s, body) = call(&f.app, "GET", "/api/v1/hosts", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body["detail"].as_str().unwrap().contains("service token"));
    let fake = "fbt_notarealtokennotarealtokennotarealtoken";
    assert_eq!(
        call(&f.app, "GET", "/api/v1/hosts", Some(fake), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // The shared client token opens the clients' /stats, never this API.
    assert_eq!(
        call(&f.app, "GET", "/api/v1/hosts", Some(CLIENT_TOKEN), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // A good token works until it is revoked, then is refused on its very next request.
    assert_eq!(
        call(&f.app, "GET", "/api/v1/whoami", Some(&f.read), None)
            .await
            .0,
        StatusCode::OK
    );
    assert!(f.db.revoke_token("mnemerynne-read", 5).unwrap());
    let (s, body) = call(&f.app, "GET", "/api/v1/whoami", Some(&f.read), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body["detail"].as_str().unwrap().contains("revoked"));
    // Every call is logged, refused ones too.
    let calls = f.db.recent_calls(10).unwrap();
    assert_eq!(calls.len(), 5); // no token, a fake one, the client token, good, revoked
    assert_eq!(calls[0].token, "mnemerynne-read (revoked)");
    assert_eq!(calls[0].status, 401);
    assert_eq!(
        (calls[1].token.as_str(), calls[1].status),
        ("mnemerynne-read", 200)
    );
    assert_eq!(calls[4].token, "-");
    assert_eq!(calls[4].path, "/api/v1/hosts");
    // The description needs no token.
    let (s, spec) = call(&f.app, "GET", "/api/v1/openapi.json", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(spec["paths"]["/disks/forecast"].is_object());
}

#[tokio::test]
async fn reads_are_lean_rows_with_units_and_iso_times() {
    let f = fixture().await;
    let t = Some(f.read.as_str());
    let (s, who) = call(&f.app, "GET", "/api/v1/whoami", t, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        (who["read"].clone(), who["act"].clone()),
        (json!(true), json!(false))
    );

    let (_, hosts) = call(&f.app, "GET", "/api/v1/hosts", t, None).await;
    assert_eq!(hosts["total"], 1);
    let row = &hosts["rows"][0];
    assert_eq!(row["status"], "up");
    assert_eq!(row["silent"], false);
    assert_eq!(row["cpu_pct"], 42.0);
    assert_eq!(row["fullest_disk_pct"], 95.0);
    assert_eq!(row["client_version"], "0.1.0");
    assert!(row["last_seen"].as_str().unwrap().ends_with('Z'));
    assert!(row.get("disks").is_none()); // detail only with /host
    let (_, silent) = call(&f.app, "GET", "/api/v1/hosts?status=silent", t, None).await;
    assert_eq!(silent["total"], 0);
    assert_eq!(
        call(&f.app, "GET", "/api/v1/hosts?status=nope", t, None)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let (s, one) = call(&f.app, "GET", "/api/v1/host?host=RSYNC-BOX", t, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(one["disks"][0]["used_pct"], 95.0);
    assert_eq!(one["disks"][0]["free_bytes"], 50);
    assert_eq!(one["listen"], "0.0.0.0:9280");
    assert!(one["issues"][0].as_str().unwrap().contains("/srv 95% full"));
    assert_eq!(
        call(&f.app, "GET", "/api/v1/host?host=nobody", t, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    let (_, sum) = call(&f.app, "GET", "/api/v1/summary", t, None).await;
    assert_eq!(
        (sum["hosts"].clone(), sum["up"].clone()),
        (json!(1), json!(1))
    );
    assert_eq!(sum["fullest_disks"][0]["mount"], "/srv");

    let (_, over) = call(&f.app, "GET", "/api/v1/over", t, None).await;
    assert_eq!(over["rows"][0]["kind"], "disk");
    let (_, over) = call(&f.app, "GET", "/api/v1/over?disk_pct=99", t, None).await;
    assert_eq!(over["total"], 0);

    let (_, clients) = call(&f.app, "GET", "/api/v1/clients", t, None).await;
    let flags = clients["rows"][0]["flags"].as_str().unwrap();
    assert!(flags.contains("listens on every address"), "{flags}");
    assert_eq!(clients["rows"][0]["binary_sha256"], "ab".repeat(32));

    let (_, th) = call(&f.app, "GET", "/api/v1/thresholds", t, None).await;
    assert_eq!(th["rows"][0]["name"], "disk_pct");
    assert_eq!(th["rows"][0]["value"], 90);
}

#[tokio::test]
async fn history_and_the_disk_forecast_use_the_rollups() {
    let f = fixture().await;
    let t = Some(f.read.as_str());
    // Five days of a disk filling by 10 bytes a day (daily rollups), ending today.
    let today = fleetboard_server::now_unix() / DAY * DAY;
    let rows: Vec<RollupRow> = (0..5u64)
        .map(|d| {
            let start = today - (4 - d) * DAY;
            let v = 910.0 + 10.0 * d as f64;
            RollupRow {
                host_id: f.host_id,
                span: DAY,
                start,
                metric: "disk:/srv".into(),
                acc: Acc {
                    min: v,
                    max: v,
                    sum: v,
                    n: 1,
                    cap: Some(1000.0),
                    first: v,
                    first_ts: start,
                    last: v,
                    last_ts: start,
                },
            }
        })
        .collect();
    f.db.upsert_rollups(&rows).unwrap();

    let (s, fc) = call(&f.app, "GET", "/api/v1/disks/forecast", t, None).await;
    assert_eq!(s, StatusCode::OK);
    let row = &fc["rows"][0];
    assert_eq!(row["mount"], "/srv");
    assert_eq!(row["growth_bytes_per_day"], 10);
    assert_eq!(row["full_in_days"], 5.0); // 50 bytes free at 10 a day
    assert!(row["basis"].as_str().unwrap().starts_with("daily"));
    let (_, none) = call(
        &f.app,
        "GET",
        "/api/v1/disks/forecast?within_days=3",
        t,
        None,
    )
    .await;
    assert_eq!(none["total"], 0);

    let (s, h) = call(
        &f.app,
        "GET",
        "/api/v1/history?host=rsync-box&metric=disk:srv&days=7",
        t,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{h}");
    assert_eq!(h["total"], 5);
    assert_eq!(h["rows"][4]["avg"], 950.0);
    assert_eq!(h["rows"][4]["used_pct"], 95.0);
    assert!(h["rows"][0]["at"].as_str().unwrap().ends_with("T00:00:00Z"));
    let (s, _) = call(
        &f.app,
        "GET",
        "/api/v1/history?host=rsync-box&metric=cpu&hours=1",
        t,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, e) = call(
        &f.app,
        "GET",
        "/api/v1/history?host=rsync-box&metric=disk:nope&days=7",
        t,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(e["detail"].as_str().unwrap().contains("disk:/srv")); // says what exists
    assert_eq!(
        call(
            &f.app,
            "GET",
            "/api/v1/history?host=rsync-box&metric=rm%20-rf",
            t,
            None
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn a_read_token_cannot_act_and_the_refusal_is_audited() {
    let f = fixture().await;
    let id = f.host_id;
    let reason = json!({"reason": "testing the refusal"});
    for path in ["pause", "resume", "remove"] {
        let (s, _) = call(
            &f.app,
            "POST",
            &format!("/api/v1/hosts/{id}/{path}"),
            Some(&f.read),
            Some(reason.clone()),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}");
    }
    let (s, _) = call(
        &f.app,
        "POST",
        "/api/v1/thresholds/disk_pct",
        Some(&f.read),
        Some(json!({"value": 80, "reason": "nope"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &f.app,
        "POST",
        "/api/v1/hosts",
        Some(&f.read),
        Some(json!({"name": "x", "address": "x:1", "reason": "nope"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(f.db.get_host(id).unwrap().unwrap().enabled); // nothing changed
    let audit = f.db.recent_audit(20, None).unwrap();
    let denied: Vec<_> = audit.iter().filter(|r| r.action == "api.denied").collect();
    assert_eq!(denied.len(), 5);
    assert_eq!(denied[0].who, "Mnemerynne/Claude (token mnemerynne-read)");
}

#[tokio::test]
async fn actions_are_audited_with_who_and_why_and_refuse_what_cant_be_done() {
    let f = fixture().await;
    let id = f.host_id;
    let t = Some(f.act.as_str());
    // A reason is required.
    let (s, _) = call(
        &f.app,
        "POST",
        &format!("/api/v1/hosts/{id}/pause"),
        t,
        Some(json!({"reason": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let (s, body) = call(
        &f.app,
        "POST",
        &format!("/api/v1/hosts/{id}/pause"),
        t,
        Some(json!({"reason": "disk swap tonight"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(!f.db.get_host(id).unwrap().unwrap().enabled);
    let (s, _) = call(
        &f.app,
        "POST",
        &format!("/api/v1/hosts/{id}/pause"),
        t,
        Some(json!({"reason": "again"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT); // already paused
    let (_, hosts) = call(&f.app, "GET", "/api/v1/hosts?status=paused", t, None).await;
    assert_eq!(hosts["total"], 1);
    let (s, _) = call(
        &f.app,
        "POST",
        &format!("/api/v1/hosts/{id}/resume"),
        t,
        Some(json!({"reason": "swap done"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, _) = call(
        &f.app,
        "POST",
        &format!("/api/v1/hosts/{id}/rename"),
        t,
        Some(json!({"name": "rsync box", "reason": "nicer name"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, e) = call(
        &f.app,
        "POST",
        "/api/v1/thresholds/disk_pct",
        t,
        Some(json!({"value": 99, "reason": "too noisy"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY); // must stay below disk_critical_pct (97)
    assert!(e["detail"].as_str().unwrap().contains("below"));
    let (s, _) = call(
        &f.app,
        "POST",
        "/api/v1/thresholds/disk_pct",
        t,
        Some(json!({"value": 85, "reason": "earlier warning"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, th) = call(&f.app, "GET", "/api/v1/thresholds", t, None).await;
    assert_eq!(th["rows"][0]["value"], 85);

    // Adding an address that doesn't answer is refused with the reason, and nothing is saved.
    let (s, e) = call(
        &f.app,
        "POST",
        "/api/v1/hosts",
        t,
        Some(json!({"name": "ghost", "address": "127.0.0.1:1", "reason": "new box"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(e["detail"].as_str().unwrap().starts_with("Not saved"));

    let (s, _) = call(
        &f.app,
        "POST",
        &format!("/api/v1/hosts/{id}/remove"),
        t,
        Some(json!({"reason": "decommissioned"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(f.db.get_host(id).unwrap().is_none());

    // The audit trail, newest first, every line from Mnemerynne/Claude with its reason.
    let (_, act) = call(&f.app, "GET", "/api/v1/activity", t, None).await;
    let rows = act["rows"].as_array().unwrap();
    let actions: Vec<&str> = rows.iter().map(|r| r["action"].as_str().unwrap()).collect();
    assert_eq!(
        actions[..5],
        [
            "host.remove",
            "threshold.set",
            "host.change",
            "host.change",
            "host.change"
        ]
    );
    for r in &rows[..5] {
        assert_eq!(r["who"], "Mnemerynne/Claude (token mnemerynne-act)");
        assert!(r["detail"].as_str().unwrap().contains("reason: "), "{r}");
    }
    assert!(rows[0]["detail"]
        .as_str()
        .unwrap()
        .contains("decommissioned"));
    assert!(rows[1]["detail"]
        .as_str()
        .unwrap()
        .contains("disk_pct 90 -> 85"));
}
