//! SQLite: the host list, 24 hours of 10-second rows, the audit log and the service tokens of the
//! `/api/v1` API (kept as SHA-256 hashes, never in the clear). One connection behind a
//! mutex (there is one writer, the poller, and a handful of readers); WAL so readers never wait.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use fleetboard_proto::HistoryPoint;
use rusqlite::{params, Connection, OptionalExtension};

use crate::bucket::SampleRow;

/// How long rows are kept.
pub const RETAIN_SECONDS: u64 = 24 * 3600;

/// One row of `api_tokens`, without the hash.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,   // who holds it, e.g. "mnemerynne-read"
    pub prefix: String, // the token's first characters, so a person can tell tokens apart
    pub scopes: String, // "read" or "read,act"
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub revoked_at: Option<u64>, // set once; a revoked token never works again
}

/// One row of `audit`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub ts: u64,
    pub who: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

/// One row of `hosts`.
#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    pub id: i64,
    pub name: String,
    pub address: String, // "host:port" as HostAddr prints it
    pub enabled: bool,
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

const SCHEMA_VERSION: i64 = 2; // 2 added api_tokens for the /api/v1 service API

impl Db {
    /// Open (creating the file and its folder) and bring the schema up to date.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("can't create {}", dir.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("can't open {}", path.display()))?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate()?;
        Ok(db)
    }

    /// An in-memory database for tests.
    pub fn in_memory() -> anyhow::Result<Self> {
        let db = Self {
            conn: Arc::new(Mutex::new(Connection::open_in_memory()?)),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Run `f` with the connection; the lock is held only for the call.
    pub fn with<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner()); // a poisoned lock still holds a fine connection
        f(&conn)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        self.with(|c| {
            c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;
            c.execute_batch("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);")?;
            let version: i64 = c.query_row("SELECT value FROM meta WHERE key = 'schema_version'", [], |r| r.get::<_, String>(0))
                .optional()?.and_then(|v| v.parse().ok()).unwrap_or(0);
            if version < 1 {
                c.execute_batch(
                    "CREATE TABLE hosts(
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                        address TEXT NOT NULL UNIQUE,
                        kind TEXT NOT NULL DEFAULT 'machine',      -- room for URL checks later
                        enabled INTEGER NOT NULL DEFAULT 1,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL);
                     CREATE TABLE samples_10s(
                        host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                        ts INTEGER NOT NULL,                       -- window start, server clock
                        n INTEGER NOT NULL,
                        cpu REAL, load1 REAL, mem_used INTEGER, mem_total INTEGER,
                        net_rx INTEGER, net_tx INTEGER, disk_used INTEGER, disk_total INTEGER,
                        gpu_util REAL, vram_used INTEGER, vram_total INTEGER, gpu_temp REAL,
                        gpus TEXT,
                        PRIMARY KEY(host_id, ts)) WITHOUT ROWID;
                     CREATE TABLE audit(
                        id INTEGER PRIMARY KEY,
                        ts INTEGER NOT NULL,
                        who TEXT NOT NULL,                         -- X-Forwarded-For: all the proxy tells us
                        action TEXT NOT NULL,
                        target TEXT NOT NULL,
                        detail TEXT NOT NULL DEFAULT '');")?;
            }
            if version < 2 {
                c.execute_batch(
                    "CREATE TABLE api_tokens(
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- who holds it, e.g. mnemerynne-read
                        hash TEXT NOT NULL UNIQUE,                 -- SHA-256 hex of the token; the token itself is never stored
                        prefix TEXT NOT NULL,                      -- the first characters, to tell tokens apart
                        scopes TEXT NOT NULL,                      -- 'read' or 'read,act'
                        created_at INTEGER NOT NULL,
                        last_used_at INTEGER,
                        revoked_at INTEGER);
                     CREATE TABLE rollups(                         -- hourly (7 days) and daily (90 days) per metric, see rollup.rs
                        host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                        span INTEGER NOT NULL,                     -- 3600 or 86400
                        metric TEXT NOT NULL,                      -- cpu, mem, disk:/, net:eth0:rx, gpu:0:temp…
                        start INTEGER NOT NULL,                    -- the hour's or UTC day's first second
                        min REAL NOT NULL, max REAL NOT NULL, sum REAL NOT NULL, n INTEGER NOT NULL,
                        cap REAL,                                  -- capacity (disk or VRAM total) when it has one
                        first REAL NOT NULL, first_ts INTEGER NOT NULL,
                        last REAL NOT NULL, last_ts INTEGER NOT NULL,
                        PRIMARY KEY(host_id, span, metric, start)) WITHOUT ROWID;
                     CREATE TABLE api_calls(                       -- every /api/v1 request, like Mnemerynne's mcp_calls
                        id INTEGER PRIMARY KEY,
                        ts INTEGER NOT NULL,
                        token TEXT NOT NULL,                       -- the token's name, or '-' when none was accepted
                        method TEXT NOT NULL,
                        path TEXT NOT NULL,                        -- with its query string
                        status INTEGER NOT NULL,
                        ms INTEGER NOT NULL);
                     CREATE INDEX api_calls_ts ON api_calls(ts);")?;
            }
            c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?1)", params![SCHEMA_VERSION.to_string()])?;
            Ok(())
        })?;
        Ok(())
    }

    // ---------------------------------------------------------------- hosts
    pub fn list_hosts(&self) -> rusqlite::Result<Vec<Host>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT id, name, address, enabled FROM hosts ORDER BY name COLLATE NOCASE",
            )?;
            let rows = st.query_map([], |r| {
                Ok(Host {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    address: r.get(2)?,
                    enabled: r.get::<_, i64>(3)? != 0,
                })
            })?;
            rows.collect()
        })
    }

    pub fn get_host(&self, id: i64) -> rusqlite::Result<Option<Host>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, name, address, enabled FROM hosts WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Host {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        address: r.get(2)?,
                        enabled: r.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()
        })
    }

    /// Add a host; the UNIQUE constraints turn duplicates into an error the API reports.
    pub fn insert_host(&self, name: &str, address: &str, now: u64) -> rusqlite::Result<Host> {
        self.with(|c| {
            c.execute(
                "INSERT INTO hosts(name, address, created_at, updated_at) VALUES(?1, ?2, ?3, ?3)",
                params![name, address, now as i64],
            )?;
            Ok(Host {
                id: c.last_insert_rowid(),
                name: name.into(),
                address: address.into(),
                enabled: true,
            })
        })
    }

    pub fn update_host(&self, host: &Host, now: u64) -> rusqlite::Result<()> {
        self.with(|c| {
            c.execute("UPDATE hosts SET name = ?1, address = ?2, enabled = ?3, updated_at = ?4 WHERE id = ?5",
                      params![host.name, host.address, host.enabled as i64, now as i64, host.id])?;
            Ok(())
        })
    }

    /// Remove a host; its samples go with it (ON DELETE CASCADE). Returns whether it existed.
    pub fn delete_host(&self, id: i64) -> rusqlite::Result<bool> {
        self.with(|c| Ok(c.execute("DELETE FROM hosts WHERE id = ?1", params![id])? > 0))
    }

    // -------------------------------------------------------------- samples
    /// Store finished windows; one transaction for the whole tick.
    pub fn insert_samples(&self, rows: &[SampleRow]) -> rusqlite::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut st = tx.prepare_cached(
                    "INSERT OR REPLACE INTO samples_10s(host_id, ts, n, cpu, load1, mem_used, mem_total, net_rx, net_tx, disk_used, disk_total,
                                                        gpu_util, vram_used, vram_total, gpu_temp, gpus)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)")?;
                for r in rows {
                    st.execute(params![r.host_id, r.ts as i64, r.n, r.cpu as f64, r.load1.map(|v| v as f64), r.mem_used as i64, r.mem_total as i64,
                                       r.net_rx as i64, r.net_tx as i64, r.disk_used as i64, r.disk_total as i64, r.gpu_util.map(|v| v as f64),
                                       r.vram_used.map(|v| v as i64), r.vram_total.map(|v| v as i64), r.gpu_temp.map(|v| v as f64), r.gpus])?;
                }
            }
            tx.commit()
        })
    }

    /// Averaged points for one host between `from` and `to`, one per `step` seconds (10, 60 or 300).
    pub fn history(
        &self,
        host_id: i64,
        from: u64,
        to: u64,
        step: u64,
    ) -> rusqlite::Result<Vec<HistoryPoint>> {
        let step = step.max(10) as i64;
        self.with(|c| {
            let mut st = c.prepare_cached(
                "SELECT (ts / ?4) * ?4 AS bucket, AVG(cpu), AVG(load1), AVG(mem_used), MAX(mem_total), AVG(net_rx), AVG(net_tx),
                        AVG(gpu_util), AVG(vram_used), AVG(gpu_temp)
                 FROM samples_10s WHERE host_id = ?1 AND ts >= ?2 AND ts < ?3
                 GROUP BY bucket ORDER BY bucket")?;
            let rows = st.query_map(params![host_id, from as i64, to as i64, step], |r| {
                Ok(HistoryPoint {
                    ts: r.get::<_, i64>(0)? as u64,
                    cpu: r.get::<_, Option<f64>>(1)?.map(|v| v as f32),
                    load1: r.get::<_, Option<f64>>(2)?.map(|v| v as f32),
                    mem_used: r.get::<_, Option<f64>>(3)?.map(|v| v as u64),
                    mem_total: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    net_rx: r.get::<_, Option<f64>>(5)?.map(|v| v as u64),
                    net_tx: r.get::<_, Option<f64>>(6)?.map(|v| v as u64),
                    gpu_util: r.get::<_, Option<f64>>(7)?.map(|v| v as f32),
                    vram_used: r.get::<_, Option<f64>>(8)?.map(|v| v as u64),
                    gpu_temp: r.get::<_, Option<f64>>(9)?.map(|v| v as f32),
                })
            })?;
            rows.collect()
        })
    }

    /// Delete rows older than the retention window and give the space back to the file.
    pub fn prune(&self, now: u64) -> rusqlite::Result<usize> {
        self.with(|c| {
            let n = c.execute(
                "DELETE FROM samples_10s WHERE ts < ?1",
                params![now.saturating_sub(RETAIN_SECONDS) as i64],
            )?;
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            Ok(n)
        })
    }

    pub fn sample_count(&self) -> rusqlite::Result<i64> {
        self.with(|c| c.query_row("SELECT count(*) FROM samples_10s", [], |r| r.get(0)))
    }

    // ---------------------------------------------------------------- audit
    /// The newest `limit` audit rows, optionally only those about one host (its name, any case).
    pub fn recent_audit(
        &self,
        limit: u32,
        target: Option<&str>,
    ) -> rusqlite::Result<Vec<AuditRow>> {
        self.with(|c| {
            let mut st = c.prepare_cached(
                "SELECT id, ts, who, action, target, detail FROM audit
                 WHERE ?2 IS NULL OR target = ?2 COLLATE NOCASE
                 ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = st.query_map(params![limit, target], |r| {
                Ok(AuditRow {
                    id: r.get(0)?,
                    ts: r.get::<_, i64>(1)? as u64,
                    who: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                    detail: r.get(5)?,
                })
            })?;
            rows.collect()
        })
    }

    pub fn audit(
        &self,
        now: u64,
        who: &str,
        action: &str,
        target: &str,
        detail: &str,
    ) -> rusqlite::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO audit(ts, who, action, target, detail) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![now as i64, who, action, target, detail],
            )?;
            Ok(())
        })
    }
}

// ------------------------------------------------------------ rollups, calls, thresholds
/// One rollup row read back: (metric, start, min, avg, max, cap, first, first_ts, last, last_ts).
#[derive(Debug, Clone, PartialEq)]
pub struct RollupPoint {
    pub metric: String,
    pub start: u64,
    pub min: f64,
    pub avg: f64,
    pub max: f64,
    pub cap: Option<f64>,
    pub first: f64,
    pub first_ts: u64,
    pub last: f64,
    pub last_ts: u64,
}

/// One logged `/api/v1` call.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ApiCall {
    pub ts: u64,
    pub token: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub ms: u64,
}

/// How long `/api/v1` calls stay in the log.
pub const KEEP_CALLS: u64 = 90 * 24 * 3600;

impl Db {
    /// Merge rollup parts into the rows already stored: min of mins, max of maxes, sums added,
    /// the earliest `first` kept and the latest `last` taken.
    pub fn upsert_rollups(&self, rows: &[crate::rollup::RollupRow]) -> rusqlite::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut st = tx.prepare_cached(
                    "INSERT INTO rollups(host_id, span, metric, start, min, max, sum, n, cap, first, first_ts, last, last_ts)
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
                     WHERE EXISTS(SELECT 1 FROM hosts WHERE id = ?1)   -- a host removed meanwhile is skipped, not an error
                     ON CONFLICT(host_id, span, metric, start) DO UPDATE SET
                        min = min(min, excluded.min), max = max(max, excluded.max),
                        sum = sum + excluded.sum, n = n + excluded.n,
                        cap = coalesce(excluded.cap, cap),
                        first = CASE WHEN excluded.first_ts < first_ts THEN excluded.first ELSE first END,
                        first_ts = min(first_ts, excluded.first_ts),
                        last = CASE WHEN excluded.last_ts >= last_ts THEN excluded.last ELSE last END,
                        last_ts = max(last_ts, excluded.last_ts)",
                )?;
                for r in rows {
                    let a = &r.acc;
                    st.execute(params![r.host_id, r.span as i64, r.metric, r.start as i64, a.min, a.max, a.sum, a.n,
                                       a.cap, a.first, a.first_ts as i64, a.last, a.last_ts as i64])?;
                }
            }
            tx.commit()
        })
    }

    /// Rollup rows of one host and span whose metric is `metric` or starts with `metric:`, from `from` on.
    pub fn rollup_series(
        &self,
        host_id: i64,
        span: u64,
        metric: &str,
        from: u64,
    ) -> rusqlite::Result<Vec<RollupPoint>> {
        self.with(|c| {
            let mut st = c.prepare_cached(
                "SELECT metric, start, min, sum / n, max, cap, first, first_ts, last, last_ts FROM rollups
                 WHERE host_id = ?1 AND span = ?2 AND (metric = ?3 OR substr(metric, 1, length(?3) + 1) = ?3 || ':')
                   AND start >= ?4
                 ORDER BY metric, start",
            )?;
            let rows = st.query_map(params![host_id, span as i64, metric, from as i64], |r| {
                Ok(RollupPoint {
                    metric: r.get(0)?,
                    start: r.get::<_, i64>(1)? as u64,
                    min: r.get(2)?,
                    avg: r.get(3)?,
                    max: r.get(4)?,
                    cap: r.get(5)?,
                    first: r.get(6)?,
                    first_ts: r.get::<_, i64>(7)? as u64,
                    last: r.get(8)?,
                    last_ts: r.get::<_, i64>(9)? as u64,
                })
            })?;
            rows.collect()
        })
    }

    /// The distinct metric names one host has rollups for (to resolve "disk:C" to "disk:C:\").
    pub fn rollup_metrics(&self, host_id: i64) -> rusqlite::Result<Vec<String>> {
        self.with(|c| {
            let mut st = c.prepare_cached(
                "SELECT DISTINCT metric FROM rollups WHERE host_id = ?1 ORDER BY metric",
            )?;
            let rows = st.query_map(params![host_id], |r| r.get(0))?;
            rows.collect()
        })
    }

    /// The newest 10-second row of a host: when it last answered, across restarts.
    pub fn last_sample_ts(&self, host_id: i64) -> rusqlite::Result<Option<u64>> {
        self.with(|c| {
            c.query_row(
                "SELECT max(ts) FROM samples_10s WHERE host_id = ?1",
                params![host_id],
                |r| r.get::<_, Option<i64>>(0),
            )
            .map(|v| v.map(|v| v as u64))
        })
    }

    /// Min, average and max of one 10-second column (`cpu`, `mem` or `load`) per `step` seconds.
    pub fn sample_series(
        &self,
        host_id: i64,
        metric: &str,
        from: u64,
        step: u64,
    ) -> rusqlite::Result<Vec<(u64, f64, f64, f64)>> {
        // Only fixed expressions reach the SQL, chosen by name: nothing from the request is spliced in.
        let expr = match metric {
            "cpu" => "cpu",
            "mem" => "100.0 * mem_used / NULLIF(mem_total, 0)",
            "load" => "load1",
            _ => return Ok(vec![]),
        };
        let step = step.max(10) as i64;
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "SELECT (ts / ?3) * ?3 AS b, min({expr}), avg({expr}), max({expr}) FROM samples_10s
                 WHERE host_id = ?1 AND ts >= ?2 AND {expr} IS NOT NULL GROUP BY b ORDER BY b"
            ))?;
            let rows = st.query_map(params![host_id, from as i64, step], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?, r.get(3)?))
            })?;
            rows.collect()
        })
    }

    /// Log one `/api/v1` call.
    pub fn log_call(&self, call: &ApiCall) -> rusqlite::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO api_calls(ts, token, method, path, status, ms) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                params![call.ts as i64, call.token, call.method, call.path, call.status, call.ms as i64],
            )?;
            Ok(())
        })
    }

    /// The newest `limit` logged calls.
    pub fn recent_calls(&self, limit: u32) -> rusqlite::Result<Vec<ApiCall>> {
        self.with(|c| {
            let mut st = c.prepare_cached(
                "SELECT ts, token, method, path, status, ms FROM api_calls ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = st.query_map(params![limit], |r| {
                Ok(ApiCall {
                    ts: r.get::<_, i64>(0)? as u64,
                    token: r.get(1)?,
                    method: r.get(2)?,
                    path: r.get(3)?,
                    status: r.get(4)?,
                    ms: r.get::<_, i64>(5)? as u64,
                })
            })?;
            rows.collect()
        })
    }

    /// A stored threshold (see `crate::thresholds`), or None when it was never set.
    pub fn get_setting(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()
        })
    }

    pub fn set_setting(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES(?1, ?2)",
                params![key, value],
            )?;
            Ok(())
        })
    }

    /// Drop rollups and logged calls past their retention (hourly 7 days, daily 90, calls 90).
    pub fn prune_long(&self, now: u64) -> rusqlite::Result<usize> {
        use crate::rollup::{DAY, HOUR, KEEP_DAILY, KEEP_HOURLY};
        self.with(|c| {
            let mut n = c.execute(
                "DELETE FROM rollups WHERE span = ?1 AND start < ?2",
                params![HOUR as i64, now.saturating_sub(KEEP_HOURLY) as i64],
            )?;
            n += c.execute(
                "DELETE FROM rollups WHERE span = ?1 AND start < ?2",
                params![DAY as i64, now.saturating_sub(KEEP_DAILY) as i64],
            )?;
            n += c.execute(
                "DELETE FROM api_calls WHERE ts < ?1",
                params![now.saturating_sub(KEEP_CALLS) as i64],
            )?;
            Ok(n)
        })
    }
}

// ------------------------------------------------------------ api tokens
const TOKEN_COLUMNS: &str = "id, name, prefix, scopes, created_at, last_used_at, revoked_at";

/// One `api_tokens` row as read with TOKEN_COLUMNS.
fn token_row(r: &rusqlite::Row) -> rusqlite::Result<ApiToken> {
    Ok(ApiToken {
        id: r.get(0)?,
        name: r.get(1)?,
        prefix: r.get(2)?,
        scopes: r.get(3)?,
        created_at: r.get::<_, i64>(4)? as u64,
        last_used_at: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
        revoked_at: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
    })
}

impl Db {
    /// Save a new token's hash; the UNIQUE name refuses a second "mnemerynne-read".
    pub fn insert_token(
        &self,
        name: &str,
        hash: &str,
        prefix: &str,
        scopes: &str,
        now: u64,
    ) -> rusqlite::Result<ApiToken> {
        self.with(|c| {
            c.execute(
                "INSERT INTO api_tokens(name, hash, prefix, scopes, created_at) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![name, hash, prefix, scopes, now as i64],
            )?;
            c.query_row(
                &format!("SELECT {TOKEN_COLUMNS} FROM api_tokens WHERE id = ?1"),
                params![c.last_insert_rowid()],
                token_row,
            )
        })
    }

    /// The token with this hash, revoked or not (the caller decides what revoked means).
    pub fn token_by_hash(&self, hash: &str) -> rusqlite::Result<Option<ApiToken>> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT {TOKEN_COLUMNS} FROM api_tokens WHERE hash = ?1"),
                params![hash],
                token_row,
            )
            .optional()
        })
    }

    /// Every token, newest first, for `fleetboard-server token list`.
    pub fn list_tokens(&self) -> rusqlite::Result<Vec<ApiToken>> {
        self.with(|c| {
            let mut st = c.prepare(&format!(
                "SELECT {TOKEN_COLUMNS} FROM api_tokens ORDER BY id DESC"
            ))?;
            let rows = st.query_map([], token_row)?;
            rows.collect()
        })
    }

    /// Revoke by name (any case). False when there's no such live token.
    pub fn revoke_token(&self, name: &str, now: u64) -> rusqlite::Result<bool> {
        self.with(|c| {
            Ok(c.execute(
                "UPDATE api_tokens SET revoked_at = ?2 WHERE name = ?1 COLLATE NOCASE AND revoked_at IS NULL",
                params![name, now as i64],
            )? > 0)
        })
    }

    /// Remember when a token was last used, at most once a minute so reads stay cheap.
    pub fn touch_token(&self, id: i64, now: u64) -> rusqlite::Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE api_tokens SET last_used_at = ?2
                 WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at < ?2 - 60)",
                params![id, now as i64],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_found_by_hash_and_revoked_by_name() {
        let db = Db::in_memory().unwrap();
        let t = db
            .insert_token("mnemerynne-read", "abc", "fbt_abcd", "read", 5)
            .unwrap();
        assert_eq!(t.scopes, "read");
        assert!(db
            .insert_token("MNEMERYNNE-READ", "def", "fbt_x", "read", 5)
            .is_err()); // names are unique in any case
        assert_eq!(db.token_by_hash("abc").unwrap().unwrap().id, t.id);
        assert!(db.token_by_hash("nope").unwrap().is_none());
        db.touch_token(t.id, 100).unwrap();
        assert_eq!(db.list_tokens().unwrap()[0].last_used_at, Some(100));
        assert!(db.revoke_token("Mnemerynne-Read", 200).unwrap());
        assert!(!db.revoke_token("mnemerynne-read", 300).unwrap()); // the first revocation stays
        assert_eq!(
            db.token_by_hash("abc").unwrap().unwrap().revoked_at,
            Some(200)
        );
    }

    #[test]
    fn recent_audit_is_newest_first_and_filters_by_host() {
        let db = Db::in_memory().unwrap();
        db.audit(1, "local", "host.add", "rds1", "a").unwrap();
        db.audit(2, "local", "host.add", "nas", "b").unwrap();
        db.audit(3, "local", "host.change", "RDS1", "c").unwrap();
        let all = db.recent_audit(10, None).unwrap();
        assert_eq!(all.iter().map(|r| r.ts).collect::<Vec<_>>(), vec![3, 2, 1]);
        assert_eq!(db.recent_audit(10, Some("rds1")).unwrap().len(), 2); // any case
        assert_eq!(db.recent_audit(1, None).unwrap()[0].detail, "c");
    }

    fn row(host_id: i64, ts: u64, cpu: f32) -> SampleRow {
        SampleRow {
            host_id,
            ts,
            n: 5,
            cpu,
            load1: None,
            mem_used: 10,
            mem_total: 100,
            net_rx: 1,
            net_tx: 2,
            disk_used: 0,
            disk_total: 0,
            gpu_util: None,
            vram_used: None,
            vram_total: None,
            gpu_temp: None,
            gpus: "[]".into(),
        }
    }

    #[test]
    fn hosts_are_unique_by_name_and_address() {
        let db = Db::in_memory().unwrap();
        let h = db.insert_host("rds1", "rds1:9280", 1).unwrap();
        assert!(db.insert_host("RDS1", "other:9280", 1).is_err()); // same name, different case
        assert!(db.insert_host("x", "rds1:9280", 1).is_err()); // same address
        assert_eq!(db.list_hosts().unwrap(), vec![h.clone()]);
        assert_eq!(db.get_host(h.id).unwrap(), Some(h));
    }

    #[test]
    fn history_downsamples_and_prune_and_cascade_remove_rows() {
        let db = Db::in_memory().unwrap();
        let h = db.insert_host("a", "a:9280", 1).unwrap();
        let rows: Vec<_> = (0..12)
            .map(|i| row(h.id, 1020 + i * 10, (i * 10) as f32))
            .collect(); // 1020..1130: two whole minutes (1020 and 1080 are multiples of 60)
        db.insert_samples(&rows).unwrap();
        let fine = db.history(h.id, 1000, 1200, 10).unwrap();
        assert_eq!(fine.len(), 12);
        let coarse = db.history(h.id, 1000, 1200, 60).unwrap();
        assert_eq!(coarse.len(), 2);
        assert_eq!(coarse[0].cpu, Some(25.0)); // average of 0,10,…,50
        assert_eq!(coarse[1].ts, 1080);
        assert_eq!(db.prune(1200 + RETAIN_SECONDS).unwrap(), 12); // everything is now older than 24 h
        db.insert_samples(&rows).unwrap();
        assert!(db.delete_host(h.id).unwrap());
        assert_eq!(db.sample_count().unwrap(), 0); // cascaded
        assert!(!db.delete_host(h.id).unwrap());
    }
}
