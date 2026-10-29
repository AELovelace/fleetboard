//! SQLite: the host list, 24 hours of 10-second rows and the audit log. One connection behind a
//! mutex (there is one writer, the poller, and a handful of readers); WAL so readers never wait.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use fleetboard_proto::HistoryPoint;
use rusqlite::{params, Connection, OptionalExtension};

use crate::bucket::SampleRow;

/// How long rows are kept.
pub const RETAIN_SECONDS: u64 = 24 * 3600;

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

const SCHEMA_VERSION: i64 = 1;

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

#[cfg(test)]
mod tests {
    use super::*;

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
