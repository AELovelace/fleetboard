# The service API (`/api/v1`)

A small REST API on the Fleetboard server for **Mnemerynne**, so Claude (through Mnemerynne's MCP
connector) and Erynne can read the fleet and propose a few changes that a person approves. It lives
on the same port as the dashboard (`127.0.0.1:9281`), under `/api/v1`, and is the only part of the
server that asks for a token.

```
Claude ──MCP──> Mnemerynne ──query_api (reads)──────────────┐
                    │                                        ├─ Bearer fbt_… ─> fleetboard-server :9281/api/v1
                    └─propose_api_action ─> person: Run it ──┘                     (127.0.0.1)
```

## Security

- **Service tokens, not the client token.** `fbt_…` tokens are made on the box with
  `fleetboard-server token add`. The shared client token (what the server sends to each client's
  `/stats`) is refused here, and service tokens never reach a client: a leak of one doesn't open
  the other.
- **Only hashes are stored** (SHA-256 in the `api_tokens` table). A token is printed once.
- **Scoped.** `read` (the default) may only read. `act` may also make the changes below. A read
  token asking for a change gets `403`, before its body is even parsed, and the refusal is audited
  (`api.denied`).
- **Revocable.** `fleetboard-server token revoke NAME` refuses the token from its very next request
  on (every request looks the hash up).
- **Every call is logged** in `api_calls`: time, token name (or `-`), method, path with query,
  status and milliseconds. `fleetboard-server calls` prints the newest. Kept 90 days.
- **Every change is audited** with who = `Mnemerynne/Claude (token NAME)` and the `reason` the
  proposal carried. A reason (3–500 characters) is required on every change.
- **Nothing shell-like.** Fleetboard's clients have no write routes at all. The changes below touch
  only Fleetboard's own host list and thresholds. In Mnemerynne they are actions: Claude can only
  propose them, and a person presses *Run it*.

## Making the tokens

On the Mnemerynne box, as the `fleetboard` user (so the database and its WAL files keep their
owner):

```bash
sudo -u fleetboard fleetboard-server token add mnemerynne-read                # read only
sudo -u fleetboard fleetboard-server token add mnemerynne-act --scope act     # reads + changes
sudo -u fleetboard fleetboard-server token list
sudo -u fleetboard fleetboard-server token revoke mnemerynne-read
sudo -u fleetboard fleetboard-server calls --limit 50
```

`token add` prints the token on stdout and a note on stderr. Paste it into Mnemerynne as the
API's credential (Bearer). The running server sees new and revoked tokens at once; no restart.

## Answers

- Lists are `{"total": n, "rows": [...]}` with flat rows, so Mnemerynne pages them and `find=` works.
- Units are in field names: `cpu_pct`, `mem_pct`, `used_bytes`, `total_bytes`, `temp_c`,
  `rx_bps`, `data_age_s`, `growth_bytes_per_day`.
- Times are UTC ISO strings (`2026-11-23T15:05:00Z`).
- Errors are `{"detail": "..."}`: `401` no/unknown/revoked token, `403` read token asked to act,
  `404` no such host or metric, `409` already paused/monitored, `422` a bad value (with the reason).
- `GET /api/v1/openapi.json` (no token) describes every route.

## Reads (any token)

| Route | Parameters | What |
|---|---|---|
| `GET /whoami` | | the token's name, `read`, `act` |
| `GET /summary` | | hosts up/down/paused/waiting/silent, the 5 busiest by CPU, the 5 fullest disks, each host's issues, the thresholds |
| `GET /hosts` | `status` = all, up, down, paused, waiting, silent, issues; `silent_minutes` | one lean row per host: status, silent, last_seen, data_age_s, hostname, os, client_version, schema, uptime_h, cpu_pct, mem_pct, fullest disk and %, hottest_c, issue count |
| `GET /host` | `host` = id, name or hostname | one host in full: facts, CPU and load, memory and swap, each disk, GPU and sensor, the 8 busiest interfaces, `listen`, `binary_sha256`, issues |
| `GET /over` | `disk_pct`, `mem_pct`, `temp_c` (default: the thresholds) | every disk, memory and temperature over a limit, and hosts silent longer than `offline_minutes` |
| `GET /disks/forecast` | `host`, `days` (2–90, default 14), `within_days` | per disk: used_pct, free_bytes, growth_bytes_per_day, full_in_days, full_by, basis; soonest-full first |
| `GET /history` | `host`, `metric`, `hours` (1–168) or `days` (1–90), `interval` (auto, 10s, 1m, 5m, 15m, 1h, 6h, 1d) | min/avg/max per interval |
| `GET /clients` | `flagged_only` | client audit: client_version, schema, os, arch, listen, binary_sha256, flags |
| `GET /activity` | `limit` (1–200), `host` | the audit log, newest first |
| `GET /thresholds` | | each limit's value, default and range |

**Metrics for `/history`:** `cpu`, `mem`, `load`, `temp` (the hottest sensor or GPU),
`disk:<mount>`, `net:<interface>` (rx and tx rows), `gpu:<n>` (utilisation, temperature, VRAM).
A bare `disk`, `net` or `gpu` gives every one. Names are matched on their letters and digits, so
`disk:C` finds `C:\` and `net:ethernet 2` finds `Ethernet (2)` (Mnemerynne's parameters can't
carry `\` or brackets). With `hours`, `cpu`/`mem`/`load` up to 24 h come from the 10-second
rows; everything else comes from the hourly rollups (7 days). With `days`, from the daily
rollups (90 days). A metric with no history yet answers 404 and lists the ones that exist.

**Disk forecast:** a least-squares line through the disk's daily averages (3 days or more), or its
hourly averages while history is shorter (6 hours or more). `full_in_days` = free bytes / growth
per day; a disk that isn't growing has none. `basis` says which was used.

**Client audit flags:**

- *listens on every address*: `listen` is `0.0.0.0:…` or `[::]:…`. That's normal for a remote
  client, provided its firewall lets only the Mnemerynne box reach the port. Check it.
- *binary differs from the other N host(s) on …*: its SHA-256 isn't the most common one among
  hosts with the same client version, OS family and architecture.
- *older client*: older than the newest version in the fleet.
- *doesn't report …*: a client from before `listen` and `binary_sha256` existed.

## Changes (act token only)

Each takes a JSON body with `reason`, and each is audited.

| Route | Body | What |
|---|---|---|
| `POST /hosts` | `name`, `address`, `reason` | add a host; it must answer with the client token first (else 422, nothing saved) |
| `POST /hosts/{id}/rename` | `name`, `reason` | rename |
| `POST /hosts/{id}/pause` | `reason` | stop polling and alerting; history stays (409 if already paused) |
| `POST /hosts/{id}/resume` | `reason` | poll again; it must answer first (409 if not paused) |
| `POST /hosts/{id}/remove` | `reason` | remove the host **and all its history**; irreversible |
| `POST /thresholds/{name}` | `value`, `reason` | set `disk_pct` (50–99), `disk_critical_pct` (50–100, above disk_pct), `mem_pct` (50–100), `temp_c` (40–120) or `offline_minutes` (1–1440) |

## Thresholds

Stored in the database (`meta`, keys `threshold.<name>`), defaults until set:

| Name | Default | Used by |
|---|---|---|
| `disk_pct` | 90 | issues, `/over`, Wazuh `disk_level` |
| `disk_critical_pct` | 97 | Wazuh `disk_critical_level` |
| `mem_pct` | 90 | issues, `/over` |
| `temp_c` | 85 | issues, `/over` (the Wazuh temperature rules stay in `server.toml`) |
| `offline_minutes` | 10 | silent hosts, `/over`, Wazuh `offline_level` |

## History kept

| What | Resolution | Kept |
|---|---|---|
| `samples_10s` | 10-second averages of the charted numbers | 24 hours |
| `rollups`, span 3600 | per hour and metric: min, max, average, first, last, capacity | 7 days |
| `rollups`, span 86400 | per UTC day and metric: the same | 90 days |
| `api_calls` | every `/api/v1` request | 90 days |

Rollups are written every 5 minutes and when an hour or day ends; parts merge into the stored row,
so a restart loses at most five minutes of them.

## In Mnemerynne

The matching API templates live in the Mnemerynne repository: `api-templates/fleetboard.json`
(reads) and `api-templates/fleetboard-actions.json` (changes). Upload them on **Access → APIs →
Upload template…**, add each, and paste the matching token. See Mnemerynne's admin help,
*Internal APIs → Fleetboard*.
