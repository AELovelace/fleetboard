# How Fleetboard works

```
 browser ──https──> Mnemerynne (/remote/fleetboard/) ──http──> fleetboard-server :9281 (127.0.0.1)
                    sign-in, group check, strips prefix          │ every 2 s, bearer token
                                                                 ├──http──> fleetboard-client :9280  (this box)
                                                                 ├──http──> fleetboard-client :9280  (rds1)
                                                                 └──http──> fleetboard-client :9280  (nas)
```

## The client (`crates/fleetboard-client`)

- `sampler.rs`: a plain thread ticks once a second (sysinfo blocks, so no async). It refreshes CPU,
  memory, disks, network and temperatures, asks every GPU collector, and publishes one `Snapshot`
  into an `Arc<RwLock<Option<Snapshot>>>`. Network rates come from the byte delta between ticks, so
  the very first tick is never published. The cadence is fixed (next = previous + 1 s), not
  "sleep 1 s after work".
- `gpu/`: one `GpuCollector` per source. `nvidia.rs` loads NVML at run time (both OSes). On Linux
  `amd_linux.rs` reads the amdgpu driver's sysfs files, which are world-readable. On Windows
  `windows_pdh.rs` reads the GPU Engine and GPU Adapter Memory performance counters and matches
  instances to DXGI adapters by LUID; it skips NVIDIA adapters when NVML already reported them.
  `detect()` logs one line per collector so a missing card is explained in the journal.
- `http.rs`: axum. `/healthz` is open; `/stats` compares the bearer token in constant time
  (`auth.rs`). Any other method is 405, bodies are capped at 1 KiB, every answer is `no-store`
  and `nosniff`, and an optional Host allow-list refuses other names.
- `run.rs`: starts both halves and stops them on a future: Ctrl-C/SIGTERM from the console, the
  Service Control Manager's Stop under Windows (`service_windows.rs`, which also logs to a daily
  file because a service has no console).

## The server (`crates/fleetboard-server`)

- `poller.rs` is modelled on Mnemerynne's balancer poller. Every two seconds it asks every enabled
  host whose turn it is (down hosts wait ten seconds between tries), with one pooled `reqwest`
  client and a one-second timeout, all hosts concurrently. It logs only when a host changes state
  ("didn't answer in time" / "answers again"). Each tick becomes one `LiveEvent` on a `broadcast`
  channel for the streams, one `RingPoint` per host (`ring.rs`, 300 points = 10 minutes) and a
  contribution to the host's current ten-second `Bucket` (`bucket.rs`); a finished bucket is one
  row in SQLite.
- `db.rs`: SQLite in WAL mode behind a mutex. `hosts`, `samples_10s` (compact columns for the
  charted series plus a JSON column for every GPU) and `audit`. `history()` downsamples in SQL
  with `GROUP BY ts / step`. Rows older than 24 h are pruned hourly.
- `api/`: `/api/hosts` (check before save, like the balancer settings), `/api/live` (SSE: first
  event at once, a `tick` per poll, `: ping` every 20 s, `bye` after five minutes), `/api/ring`,
  `/api/history`, `/healthz`, and the embedded `web/` files with an ETag.
- Timestamps are the server's clock throughout; the client's `taken_at` is for display.

## Why it looks the way it does behind Mnemerynne's proxy

Mnemerynne strips `/remote/fleetboard` before forwarding and sends no user identity, so every URL
in the page is relative, the server has no sign-in of its own, and the audit log can only record
`X-Forwarded-For`. The proxy checks the person's session only when a request starts, so a stream
says goodbye every five minutes and the browser reconnects; a 401 on reconnect means "signed out"
and the page says so instead of retrying. HTML rewriting in the proxy is left off (relative URLs
make it unnecessary) and WebSockets are avoided (the proxy forwards Mnemerynne's `Origin`). The
theme follows the parent frame's `data-theme` with neon as the default.

## Trust

The client's token is a shared secret on the LAN: anyone who has it can read a machine's stats,
nothing more (the client has no write routes). The server has no secrets besides that token and
is reachable only from the box it runs on. Who may *see* the dashboard is entirely Mnemerynne's
group setting on the Remote app.
