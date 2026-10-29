//! End to end inside one process: a real client router on an ephemeral port, polled by a real
//! Poller with an in-memory database. Proves the two binaries agree on the wire format and the
//! token, and that a wrong token is reported in words.

use std::sync::{Arc, RwLock};

use fleetboard_client::http::{router, AppState};
use fleetboard_proto::{Cpu, HostFacts, Memory, Snapshot, SCHEMA};
use fleetboard_server::addr::HostAddr;
use fleetboard_server::db::{Db, Host};
use fleetboard_server::poller::Poller;

const TOKEN: &str = "integration-test-token-abcdefgh";

/// Start a client that already has one snapshot, on 127.0.0.1:<random>; returns "host:port".
async fn start_client() -> String {
    let snap = Snapshot {
        schema: SCHEMA,
        taken_at: 1,
        host: HostFacts {
            hostname: "testbox".into(),
            os: "TestOS".into(),
            arch: "x86_64".into(),
            agent: "0.1.0".into(),
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
        disks: vec![],
        network: vec![],
        gpus: vec![],
        temperatures: vec![],
    };
    let state = AppState {
        latest: Arc::new(RwLock::new(Some(snap))),
        token: TOKEN.into(),
        allowed_hosts: Arc::new(vec![]),
        hostname: "testbox".into(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

#[tokio::test]
async fn the_server_polls_a_real_client_and_a_wrong_token_is_explained() {
    let address = start_client().await;
    let db = Db::in_memory().unwrap();
    let host = db.insert_host("testbox", &address, 1).unwrap();

    let poller = Poller::new(db.clone(), TOKEN.into(), vec![host.clone()]);
    let ok = poller
        .check(&HostAddr::parse(&address).unwrap())
        .await
        .unwrap();
    assert_eq!((ok.hostname.as_str(), ok.schema), ("testbox", SCHEMA));

    poller.poll_once().await;
    let rows = poller.view();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reachable, Some(true));
    assert!(rows[0].latency_ms.is_some());
    assert_eq!(rows[0].snapshot.as_ref().unwrap().cpu.percent, 42.0);
    assert_eq!(poller.ring(host.id).unwrap().len(), 1);

    let wrong = Poller::new(db, "wrong-token-wrong-token-wrong-tok".into(), vec![host]);
    let err = wrong
        .check(&HostAddr::parse(&address).unwrap())
        .await
        .unwrap_err();
    assert_eq!(err, "rejected the token");
    wrong.poll_once().await;
    let rows = wrong.view();
    assert_eq!(rows[0].reachable, Some(false));
    assert_eq!(rows[0].error, "rejected the token");

    // A port that was just released: nothing listens, so the connection is refused at once
    // (a random closed port could be silently dropped by a firewall and time out instead).
    let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = format!("127.0.0.1:{}", free.local_addr().unwrap().port());
    drop(free);
    let dead = Poller::new(
        Db::in_memory().unwrap(),
        TOKEN.into(),
        vec![Host {
            id: 9,
            name: "gone".into(),
            address: closed,
            enabled: true,
        }],
    );
    dead.poll_once().await;
    // Windows sometimes answers a closed loopback port with silence instead of a reset, so either
    // "down" text is right; what matters is that the host is marked down with a readable reason.
    let error = dead.view()[0].error.clone();
    assert_eq!(dead.view()[0].reachable, Some(false));
    assert!(
        error.contains("refused the connection") || error.contains("didn't answer in time"),
        "{error}"
    );
}
