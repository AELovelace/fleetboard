# Wire format

All JSON, all `snake_case`, defined once in `crates/fleetboard-proto`. Units: bytes, bytes per
second (`_bps`), percent 0–100 as a float, °C, watts, MHz, seconds. A field that a platform or
driver doesn't expose is `null` (an `Option`), and lists may be empty.

**Versioning.** `schema` is `1`. It is bumped only for a breaking change. New fields are added
with a default so an older server still reads a newer client, and unknown fields are ignored. A
server refuses a client whose `schema` is higher than its own with "client too new; update the
server".

## Client → server

### `GET /healthz` (no token)

```json
{"status":"ok","schema":1,"agent":"0.1.0","hostname":"rds1"}
```

### `GET /stats` (`Authorization: Bearer <token>`)

A `Snapshot`; `503 {"detail":"Warming up: no sample yet"}` for the first second after start.

| Field | Type | Meaning |
|---|---|---|
| `schema` | int | 1 |
| `taken_at` | int | client unix seconds (display only) |
| `host.hostname`, `host.name` | string, string\|null | the machine's name and the config's display name |
| `host.os`, `host.kernel`, `host.arch` | string | "Fedora Linux 42", "6.11.5", "x86_64" |
| `host.uptime_s`, `host.agent` | int, string | seconds up; the client version |
| `cpu.percent`, `cpu.per_core[]` | float | utilisation 0–100 |
| `cpu.cores`, `cpu.model`, `cpu.freq_mhz` | int, string, int\|null | logical cores, model, current clock |
| `cpu.load1/5/15` | float\|null | Unix load averages, null on Windows |
| `memory.used_bytes`, `total_bytes`, `available_bytes` | int | RAM |
| `memory.swap_used_bytes`, `swap_total_bytes` | int | swap / page file |
| `disks[].mount`, `device`, `fs`, `used_bytes`, `total_bytes` | | real filesystems only |
| `network[].name`, `rx_bps`, `tx_bps`, `rx_total`, `tx_total` | | rates over the last tick; loopback left out |
| `gpus[].index`, `vendor`, `name`, `source` | int, "nvidia"\|"amd"\|"intel"\|"other", string, "nvml"\|"amdgpu-sysfs"\|"pdh" | which collector read it |
| `gpus[].util_percent`, `vram_used_bytes`, `vram_total_bytes`, `temp_c`, `power_w`, `fan_percent`, `fan_rpm`, `clock_mhz` | all nullable | what the source exposes |
| `temperatures[].label`, `celsius`, `max_c` | | other sensors (CPU, NVMe); mostly Linux |

What each GPU source fills in:

| Source | util | VRAM | temp | power | fan | clock |
|---|---|---|---|---|---|---|
| `nvml` (NVIDIA, both OSes) | yes | yes | yes | yes | % | yes |
| `amdgpu-sysfs` (AMD, Linux) | yes | yes | yes | yes | rpm and % | no |
| `pdh` (any, Windows) | yes | used; total from DXGI | no | no | no | no |

## Server → browser

### `GET /api/live` (Server-Sent Events)

The first event is the current state. Then one `tick` per poll (every 2 s), a `: ping` comment
every 20 s, and after five minutes `event: bye` followed by a clean close so the browser reconnects.

```
event: tick
data: {"ts":1761600000,"hosts":[
  {"id":1,"name":"mnemerynne","address":"127.0.0.1:9280","enabled":true,"reachable":true,"error":"",
   "polled_s_ago":0,"latency_ms":3,"snapshot":{…Snapshot…}},
  {"id":2,"name":"rds1","address":"10.0.5.9:9280","enabled":true,"reachable":false,
   "error":"didn't answer in time","polled_s_ago":4,"latency_ms":null,"snapshot":{…last good one…}}]}
```

`reachable` is `null` for a host never asked yet (just added, or disabled). `snapshot` keeps the
last good answer while a host is down so the card still shows what the machine is.

### `GET /api/hosts`

`{"hosts":[HostLive…],"token_set":true}`. `POST /api/hosts {"name","address"}` checks the address
first and answers `201` with the new `HostLive`, or `422 {"detail":"Not saved: rds1:9280 rejected
the token."}`. `PUT /api/hosts/{id} {"name"?,"address"?,"enabled"?}`, `DELETE /api/hosts/{id}`
(204), `POST /api/hosts/check {"address"}` → `{"ok":true,"address":"rds1:9280","latency_ms":12,
"hostname":"rds1","agent":"0.1.0"}`.

### `GET /api/ring?host=ID`

`{"host":1,"points":[{"ts","cpu","mem_used","gpu_util","net_rx","net_tx"}…]}`, oldest first, at
most 300 (ten minutes).

### `GET /api/history?host=ID&from=U&to=U&step=10|60|300`

`{"host":1,"from":…,"to":…,"step":60,"points":[{"ts","cpu","load1","mem_used","mem_total",
"net_rx","net_tx","gpu_util","vram_used","gpu_temp"}…]}`. The range is clamped to the last 24 h and
the step raised until at most 1440 points come back. Missing windows (host down) are simply absent.

### Errors

Every error is `{"detail": "a sentence"}` with the usual status: 404 unknown host, 409 duplicate
name or address, 422 invalid or unreachable, 500 database.
