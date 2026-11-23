# Changelog

All notable changes, newest first. Format after [Keep a Changelog](https://keepachangelog.com/);
the release workflow copies the top section into the GitHub release notes.

## Unreleased

- **Windows installer**: `-KeepOptions` updates a client without retyping anything (the existing
  `client.toml` and firewall rule are kept), and an update now stops the running service before
  replacing its binary, which the running service had held open.

## 0.2.0 - 2026-11-23

Update the server first (its database moves to schema 2 on start), then the clients when
convenient; 0.1.0 clients keep working. Copy the new `deploy/wazuh/fleetboard_rules.xml` to the
Wazuh manager for the disk and offline alerts.

- **Service API for Mnemerynne** (`/api/v1`, see [API.md](API.md)): scoped, revocable `fbt_`
  service tokens stored as SHA-256 hashes (`fleetboard-server token add|list|revoke`), separate
  from the shared client token. Reads: summary, hosts (with silent hosts), host detail, over
  thresholds, disk forecast, history, client audit, activity, thresholds. Changes (act tokens
  only, each audited as `Mnemerynne/Claude (token …)` with a reason): add, rename, pause, resume
  and remove a host, set a threshold. Every call logged in `api_calls` (`fleetboard-server calls`).
  Hand-written OpenAPI at `/api/v1/openapi.json`. Mnemerynne templates in the Mnemerynne repo.
- **Longer history**: hourly (7 days) and daily (90 days) min/avg/max per metric, per disk,
  interface and GPU, in a new `rollups` table. Schema version 2.
- **Thresholds** in the database (`disk_pct`, `disk_critical_pct`, `mem_pct`, `temp_c`,
  `offline_minutes`), shared by the API and the Wazuh alerts.
- **Wazuh disk-full and offline alerts** (`disk_level`, `disk_critical_level`,
  `disk_hysteresis_pct`, `offline_level` under `[wazuh]`), for machines without their own Wazuh
  agent. Every alert line now has a `message`; the manager's rules use it as the description.
- **Client** reports `host.listen` (its bind address) and `host.binary_sha256` (its own
  executable's SHA-256) for the client audit. Both optional on the wire; schema stays 1.
- **Wazuh temperature alerts**: `[wazuh]` and `[[wazuh.temperature]]` in `server.toml` set
  which temperature is which Wazuh level, per sensor and per host, with hysteresis, repeats and a
  "recovered" line. The server appends JSON lines to `/var/log/fleetboard/wazuh-alerts.json`
  for the local Wazuh agent; `deploy/wazuh/` has the agent snippet and the manager's rules.
  `install-server.sh` writes an example section and `LogsDirectory=fleetboard`; with
  `--keep-options` it now keeps `server.toml` as well as `server.env`.
- **Windows counters**: Microsoft's Basic Render Driver is skipped by vendor and name too, so a
  headless server no longer shows the software adapter as a GPU.

## 0.1.0 - 2026-10-28

First release.

- **Client**: CPU (total, per core, load averages, clock), memory and swap, real disks, network
  rates, temperatures; GPUs through NVML (NVIDIA, both OSes), amdgpu sysfs (AMD on Linux) and
  Windows performance counters (any vendor; utilisation and VRAM). `/healthz` open, `/stats`
  behind a shared bearer token compared in constant time. Runs as a systemd service or a Windows
  service (`service install`), logs to the journal or a daily file. `once`, `gen-token`,
  `check-config`.
- **Server**: polls every host every 2 s with a 1 s timeout (down hosts every 10 s), keeps 10
  minutes in memory and 24 hours of 10-second averages in SQLite, prunes hourly. Hosts API with
  check-before-save and an audit log keyed on `X-Forwarded-For`. SSE live stream with a 5-minute
  lifetime so Mnemerynne's proxy re-checks access. History API with SQL downsampling.
- **Dashboard**: live cards (CPU, memory, GPUs, network, disks, sparklines), a Hosts tab, a 24-hour
  History tab with a time scrubber, Erynne's three themes read from the parent frame, reconnect
  with backoff and a "signed out" banner. Relative URLs only; no framework.
- **Deploy**: `install-server.sh`, `install-client.sh`, `Install-FleetboardClient.ps1` with
  checksum verification, `--dry-run`/`-WhatIf`, `--check`, `--uninstall`; GitHub Actions CI and a
  release workflow for Windows and Linux binaries with `SHA256SUMS`.
