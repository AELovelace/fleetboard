//! The poll loop, modelled on Mnemerynne's balancer poller (`mnemerynne/balancer.py`): every two
//! seconds ask every enabled host for `/stats`, remember the answer, log only when a host changes
//! state, broadcast one [`LiveEvent`] to the dashboard streams, and roll finished 10-second windows
//! into SQLite. A host that is down is asked every ten seconds instead so the LAN isn't hammered.
//! The loop never dies: any error is logged and the next tick happens anyway.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fleetboard_proto::{HostLive, LiveEvent, RingPoint, Snapshot, SCHEMA};
use tokio::sync::broadcast;

use crate::addr::HostAddr;
use crate::bucket::{Bucket, SampleRow};
use crate::db::{Db, Host};
use crate::ring::Ring;
use crate::rollup::{RollupRow, Rollups};
use crate::thresholds::Thresholds;
use crate::wazuh::{AlertLine, AlertLog, DiskAlerts, HostAlerts, WazuhConfig};

/// How often the open hours and days are written to the database (they merge on conflict).
pub const ROLLUP_FLUSH_SECONDS: u64 = 300;

pub const POLL_SECONDS: u64 = 2;
pub const POLL_TIMEOUT: Duration = Duration::from_millis(1000);
pub const CHECK_TIMEOUT: Duration = Duration::from_millis(5000);
pub const DOWN_POLL_SECONDS: u64 = 10;
pub const MAX_HOSTS: usize = 64;

/// What the poller remembers about one host between ticks.
pub struct HostState {
    pub host: Host,
    pub reachable: Option<bool>, // None: never asked (just added, or disabled)
    pub error: String,
    pub polled_at: Option<u64>, // server clock of the last attempt
    pub latency_ms: Option<u32>,
    pub latest: Option<Snapshot>, // kept while down so the card still shows facts
    pub ring: Ring,
    pub bucket: Bucket,
    pub rollups: Rollups,        // the open hour and day for the long history
    pub last_ok_at: Option<u64>, // server clock of the last good answer (since this start)
    pub down_since: Option<u64>, // when it stopped answering; None while it answers
    alerts: HostAlerts,          // each sensor's Wazuh level
    disk_alerts: DiskAlerts,     // each disk's Wazuh stage
    offline_alert: Option<u64>,  // Some(last line sent) while an offline alert stands
    next_poll: Instant,
}

/// One host as the API sees it: the dashboard's row plus when it last answered.
#[derive(Debug, Clone)]
pub struct HostStatus {
    pub live: HostLive,
    pub last_ok_at: Option<u64>,
    pub down_since: Option<u64>,
}

impl HostState {
    fn new(host: Host) -> Self {
        let bucket = Bucket::new(host.id);
        let rollups = Rollups::new(host.id);
        Self {
            host,
            reachable: None,
            error: String::new(),
            polled_at: None,
            latency_ms: None,
            latest: None,
            ring: Ring::default(),
            bucket,
            rollups,
            last_ok_at: None,
            down_since: None,
            alerts: HostAlerts::new(),
            disk_alerts: DiskAlerts::new(),
            offline_alert: None,
            next_poll: Instant::now(),
        }
    }

    fn view(&self, now: u64) -> HostLive {
        HostLive {
            id: self.host.id,
            name: self.host.name.clone(),
            address: self.host.address.clone(),
            enabled: self.host.enabled,
            reachable: self.reachable,
            error: self.error.clone(),
            polled_s_ago: self.polled_at.map(|t| now.saturating_sub(t)),
            latency_ms: self.latency_ms,
            snapshot: self.latest.clone(),
        }
    }
}

/// What `check` learned from a host that answered properly.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CheckOk {
    pub latency_ms: u32,
    pub hostname: String,
    pub agent: String,
    pub schema: u32,
}

/// One poll's result, applied under the lock afterwards.
struct Outcome {
    id: i64,
    result: Result<(Snapshot, u32), String>,
}

pub struct Poller {
    client: reqwest::Client,
    token: String,
    hosts: Mutex<Vec<HostState>>,
    tx: broadcast::Sender<Arc<LiveEvent>>,
    db: Db,
    wazuh: Option<(WazuhConfig, AlertLog)>, // None when alerts are off
    thresholds: Mutex<Thresholds>, // disk/offline limits, changed by the API's Set threshold
    rollups_flushed_at: Mutex<u64>, // when the open hours and days last went to disk
}

impl Poller {
    pub fn new(db: Db, token: String, hosts: Vec<Host>) -> Arc<Self> {
        Self::with_wazuh(db, token, hosts, WazuhConfig::default())
    }

    /// Like `new`, and checks every temperature against `wazuh` when it is enabled.
    pub fn with_wazuh(db: Db, token: String, hosts: Vec<Host>, wazuh: WazuhConfig) -> Arc<Self> {
        let wazuh = wazuh.enabled.then(|| {
            let log = AlertLog::new(&wazuh);
            (wazuh, log)
        });
        let client = reqwest::Client::builder()
            .timeout(POLL_TIMEOUT)
            .pool_max_idle_per_host(2)
            .build()
            .expect("reqwest client");
        let (tx, _) = broadcast::channel(32);
        let thresholds = Mutex::new(Thresholds::load(&db)); // stored limits, defaults until set
        Arc::new(Self {
            client,
            token,
            hosts: Mutex::new(hosts.into_iter().map(HostState::new).collect()),
            tx,
            db,
            wazuh,
            thresholds,
            rollups_flushed_at: Mutex::new(crate::now_unix()),
        })
    }

    /// The limits the audit operations and the Wazuh disk/offline alerts use now.
    pub fn thresholds(&self) -> Thresholds {
        *self.thresholds.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Use new limits from the next poll on (the API saved them first).
    pub fn set_thresholds(&self, t: Thresholds) {
        *self.thresholds.lock().unwrap_or_else(|e| e.into_inner()) = t;
    }

    /// Every host with when it last answered and since when it is down, for the API.
    pub fn statuses(&self) -> Vec<HostStatus> {
        let now = crate::now_unix();
        self.lock()
            .iter()
            .map(|s| HostStatus {
                live: s.view(now),
                last_ok_at: s.last_ok_at,
                down_since: s.down_since,
            })
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<HostState>> {
        self.hosts.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Replace the host list; hosts whose id stays keep their state (ring, bucket, reachability).
    pub fn configure(&self, hosts: Vec<Host>) {
        let mut guard = self.lock();
        let mut old: HashMap<i64, HostState> = guard.drain(..).map(|s| (s.host.id, s)).collect();
        for host in hosts {
            let mut state = old
                .remove(&host.id)
                .unwrap_or_else(|| HostState::new(host.clone()));
            if state.host.address != host.address || (!state.host.enabled && host.enabled) {
                state.reachable = None; // a new address starts fresh
                state.error.clear();
                state.next_poll = Instant::now();
            }
            if !host.enabled {
                state.reachable = None;
                state.error.clear();
            }
            state.host = host;
            guard.push(state);
        }
        // Hosts that vanished: their last window goes to the database before they are forgotten.
        let rows: Vec<SampleRow> = old.values_mut().filter_map(|s| s.bucket.finish()).collect();
        drop(guard);
        if let Err(e) = self.db.insert_samples(&rows) {
            tracing::warn!("couldn't store the last window of removed hosts: {e}");
        }
    }

    /// The dashboard's rows.
    pub fn view(&self) -> Vec<HostLive> {
        let now = crate::now_unix();
        self.lock().iter().map(|s| s.view(now)).collect()
    }

    pub fn ring(&self, id: i64) -> Option<Vec<RingPoint>> {
        self.lock()
            .iter()
            .find(|s| s.host.id == id)
            .map(|s| s.ring.points())
    }

    pub fn host_count(&self) -> (usize, usize) {
        let g = self.lock();
        (
            g.len(),
            g.iter().filter(|s| s.reachable == Some(true)).count(),
        )
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LiveEvent>> {
        self.tx.subscribe()
    }

    /// The current state as one event, for a stream that just connected.
    pub fn current_event(&self) -> Arc<LiveEvent> {
        Arc::new(LiveEvent {
            ts: crate::now_unix(),
            hosts: self.view(),
        })
    }

    /// Ask one address whether it is a Fleetboard client that accepts our token (before saving it).
    pub async fn check(&self, addr: &HostAddr) -> Result<CheckOk, String> {
        let started = Instant::now();
        let res = self
            .client
            .get(format!("{}/stats", addr.url()))
            .bearer_auth(&self.token)
            .timeout(CHECK_TIMEOUT)
            .send()
            .await
            .map_err(|e| why(&e))?;
        let code = res.status();
        if !code.is_success() {
            return Err(status_error(code.as_u16()));
        }
        let snap: Snapshot = res
            .json()
            .await
            .map_err(|_| "isn't a Fleetboard client (unexpected answer)".to_string())?;
        if snap.schema > SCHEMA {
            return Err(format!(
                "client too new (schema {}); update the server",
                snap.schema
            ));
        }
        Ok(CheckOk {
            latency_ms: started.elapsed().as_millis() as u32,
            hostname: snap.host.hostname,
            agent: snap.host.agent,
            schema: snap.schema,
        })
    }

    /// One tick: poll everyone who is due, apply the answers, broadcast, store finished windows.
    pub async fn poll_once(&self) {
        let now_i = Instant::now();
        let due: Vec<(i64, HostAddr)> = self
            .lock()
            .iter()
            .filter(|s| s.host.enabled && s.next_poll <= now_i)
            .filter_map(|s| {
                HostAddr::parse(&s.host.address)
                    .ok()
                    .map(|a| (s.host.id, a))
            })
            .collect();
        let outcomes =
            futures::future::join_all(due.into_iter().map(|(id, addr)| self.poll_host(id, addr)))
                .await;
        let now = crate::now_unix();
        let mut rows = Vec::new();
        let mut rollup_rows: Vec<RollupRow> = Vec::new();
        let mut alerts: Vec<AlertLine> = Vec::new();
        let th = self.thresholds();
        let flush_rollups = {
            let mut at = self
                .rollups_flushed_at
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let due = now.saturating_sub(*at) >= ROLLUP_FLUSH_SECONDS;
            if due {
                *at = now;
            }
            due
        };
        {
            let mut guard = self.lock();
            for o in outcomes {
                let Some(s) = guard.iter_mut().find(|s| s.host.id == o.id) else {
                    continue;
                };
                s.polled_at = Some(now);
                match o.result {
                    Ok((snap, ms)) => {
                        if s.reachable == Some(false) {
                            tracing::info!(
                                "Host {} ({}) answers again.",
                                s.host.name,
                                s.host.address
                            );
                        }
                        s.reachable = Some(true);
                        s.error.clear();
                        s.latency_ms = Some(ms);
                        s.ring.push(now, &snap);
                        if let Some(row) = s.bucket.push(now, &snap) {
                            rows.push(row);
                        }
                        rollup_rows.extend(s.rollups.push(now, &snap)); // an hour or day that just closed
                        s.last_ok_at = Some(now);
                        s.down_since = None;
                        if let Some((rules, _)) = &self.wazuh {
                            alerts.extend(rules.evaluate(&s.host, &snap, &mut s.alerts, now));
                            alerts.extend(rules.evaluate_disks(
                                &s.host,
                                &snap,
                                &th,
                                &mut s.disk_alerts,
                                now,
                            ));
                            alerts.extend(rules.evaluate_offline(
                                &s.host,
                                None,
                                "",
                                &th,
                                &mut s.offline_alert,
                                now,
                            ));
                        }
                        s.latest = Some(snap);
                        s.next_poll = now_i + Duration::from_secs(POLL_SECONDS);
                    }
                    Err(reason) => {
                        if s.reachable != Some(false) {
                            tracing::warn!("Host {} ({}): {}", s.host.name, s.host.address, reason);
                        }
                        s.reachable = Some(false);
                        s.error = reason;
                        s.latency_ms = None;
                        s.next_poll = now_i + Duration::from_secs(DOWN_POLL_SECONDS);
                        let since = *s.down_since.get_or_insert(now);
                        if let Some((rules, _)) = &self.wazuh {
                            alerts.extend(rules.evaluate_offline(
                                &s.host,
                                Some(since),
                                &s.error,
                                &th,
                                &mut s.offline_alert,
                                now,
                            ));
                        }
                    }
                }
            }
            if flush_rollups {
                rollup_rows.extend(guard.iter_mut().flat_map(|s| s.rollups.drain()));
            }
        }
        let event = self.current_event();
        let _ = self.tx.send(event); // no listeners is fine
        if let Some((_, log)) = &self.wazuh {
            log.write(&alerts);
        }
        if let Err(e) = self.db.insert_samples(&rows) {
            tracing::warn!("couldn't store samples: {e}");
        }
        if let Err(e) = self.db.upsert_rollups(&rollup_rows) {
            tracing::warn!("couldn't store the hourly and daily rollups: {e}");
        }
    }

    async fn poll_host(&self, id: i64, addr: HostAddr) -> Outcome {
        let started = Instant::now();
        let result = async {
            let res = self
                .client
                .get(format!("{}/stats", addr.url()))
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(|e| why(&e))?;
            let code = res.status();
            if !code.is_success() {
                return Err(status_error(code.as_u16()));
            }
            let snap: Snapshot = res
                .json()
                .await
                .map_err(|_| "isn't a Fleetboard client (unexpected answer)".to_string())?;
            if snap.schema > SCHEMA {
                return Err(format!(
                    "client too new (schema {}); update the server",
                    snap.schema
                ));
            }
            Ok((snap, started.elapsed().as_millis() as u32))
        }
        .await;
        Outcome { id, result }
    }

    /// Tick forever at a fixed cadence; a slow tick skips, it never bunches up.
    pub async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(POLL_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.poll_once().await; // every error inside is caught and logged
        }
    }

    /// Flush every open window (shutdown).
    pub fn flush(&self) {
        let (rows, rollups): (Vec<SampleRow>, Vec<RollupRow>) = {
            let mut guard = self.lock();
            let rows = guard.iter_mut().filter_map(|s| s.bucket.finish()).collect();
            let rollups = guard.iter_mut().flat_map(|s| s.rollups.drain()).collect();
            (rows, rollups)
        };
        if let Err(e) = self.db.insert_samples(&rows) {
            tracing::warn!("couldn't store the last windows: {e}");
        }
        if let Err(e) = self.db.upsert_rollups(&rollups) {
            tracing::warn!("couldn't store the last rollups: {e}");
        }
    }
}

/// A transport error in words an admin can act on.
pub fn why(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        "didn't answer in time".into()
    } else if err.is_connect() {
        "refused the connection (not running, or a firewall)".into()
    } else {
        let text = err.to_string();
        text.chars().take(200).collect()
    }
}

/// An HTTP status in words.
pub fn status_error(code: u16) -> String {
    match code {
        401 | 403 => "rejected the token".into(),
        404 => "isn't a Fleetboard client (no /stats)".into(),
        503 => "is still warming up".into(),
        c => format!("answered HTTP {c}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_texts_are_readable() {
        assert_eq!(status_error(401), "rejected the token");
        assert_eq!(status_error(404), "isn't a Fleetboard client (no /stats)");
        assert_eq!(status_error(500), "answered HTTP 500");
    }
}
