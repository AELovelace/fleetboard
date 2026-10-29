# Changelog

All notable changes, newest first. Format after [Keep a Changelog](https://keepachangelog.com/);
the release workflow copies the top section into the GitHub release notes.

## 0.1.0 - unreleased

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
