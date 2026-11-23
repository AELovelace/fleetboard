# Fleetboard

Fleetboard shows the load of every server and PC in one place: CPU, load average, memory, disks,
network and GPUs (NVIDIA and AMD), updated every two seconds, with the last 24 hours kept for a
look back. It lives inside **Erynne** as a [Remote app](docs/MNEMERYNNE-SETUP.md): Mnemerynne
handles sign-in and decides who may open it, Fleetboard only draws.

Two small Rust programs, one repo:

- **fleetboard-client** runs on every machine. It measures once a second and answers two HTTP
  routes: `/healthz` (who am I) and `/stats` (the full picture, behind a shared bearer token).
  One static-ish binary per OS, no runtime to install.
- **fleetboard-server** runs on the Mnemerynne box. It polls every client, keeps ten minutes in
  memory, 24 hours of ten-second averages, 7 days hourly and 90 days daily in SQLite, and serves
  the dashboard and its live stream. It binds to 127.0.0.1 and trusts Mnemerynne's proxy. It also
  has a token-authenticated **service API** (`/api/v1`) so Claude, through Mnemerynne, can read
  the fleet and propose changes a person approves: see [docs/API.md](docs/API.md).

## Ports

| Port | What | Reachable from |
|---|---|---|
| 9280 | client: `/healthz` (open), `/stats` (bearer token) | the Mnemerynne box only (the installers add the firewall rule) |
| 9281 | server: dashboard, `/api/*`, `/healthz`; `/api/v1/*` (service token) | this machine only; people open `https://<erynne>/remote/fleetboard/`, Mnemerynne calls `http://127.0.0.1:9281/api/v1` |

## Claude and Mnemerynne's API presets

Make two service tokens on the box and give them to Mnemerynne's two built-in Fleetboard API
presets, **Fleetboard** and **Fleetboard (changes)** (Access → APIs, pick the preset, **Add**):

```bash
sudo -u fleetboard fleetboard-server token add mnemerynne-read               # reads only
sudo -u fleetboard fleetboard-server token add mnemerynne-act --scope act    # reads + changes
```

They are not the shared client token, are stored only as hashes, and are revoked with
`fleetboard-server token revoke NAME`. Every call is logged (`fleetboard-server calls`) and every
change is audited with the reason. Details in [docs/API.md](docs/API.md).

## Install

Binaries come from [GitHub Releases](https://github.com/AELovelace/fleetboard/releases); the
installers download the latest one and check it against `SHA256SUMS`. Make one token and use it
everywhere: `fleetboard-client gen-token` (or `fleetboard-server gen-token`).

**Server, on the Mnemerynne box (Fedora), as root:**

```bash
curl -fsSL https://raw.githubusercontent.com/AELovelace/fleetboard/main/deploy/linux/install-server.sh -o install-server.sh
bash install-server.sh --token TOKEN
bash install-client.sh --token TOKEN --bind 127.0.0.1:9280     # the box watches itself over loopback
```

**Client, on a Linux box, as root:**

```bash
curl -fsSL https://raw.githubusercontent.com/AELovelace/fleetboard/main/deploy/linux/install-client.sh -o install-client.sh
bash install-client.sh --token TOKEN --allow-from <mnemerynne-ip>/32 [--name "NAS"]
bash install-client.sh --check
```

**Client, on Windows, in an administrator PowerShell:**

```powershell
.\Install-FleetboardClient.ps1 -Token TOKEN -ServerIp <mnemerynne-ip> [-Name "RDS 1"]
.\Install-FleetboardClient.ps1 -Check
```

**Updating a client** to the latest release keeps its token, bind, name and firewall rule:

```bash
bash install-client.sh --keep-options                 # Linux, as root
```
```powershell
.\Install-FleetboardClient.ps1 -KeepOptions           # Windows, administrator PowerShell
```

Then add each machine under **Hosts** in the dashboard: name, `address[:port]`, **Check**, **Add**.
A host is only saved once it answers with the token.

Every installer takes `--dry-run` (PowerShell: `-WhatIf`), `--check`, `--uninstall` and
`--keep-options` (PowerShell: `-KeepOptions`; reinstall or update without retyping the token). What they write:

| Installer | Writes |
|---|---|
| `install-server.sh` | `/usr/local/bin/fleetboard-server`, `/etc/fleetboard/server.env` (0640, the token), `/etc/fleetboard/server.toml`, `/etc/systemd/system/fleetboard-server.service`, user `fleetboard`, `/var/lib/fleetboard/fleetboard.db` |
| `install-client.sh` | `/usr/local/bin/fleetboard-client`, `/etc/fleetboard/client.toml` (0640), `/etc/systemd/system/fleetboard-client.service`, user `fleetboard-client` (groups render, video), a firewalld/ufw rule for 9280 from `--allow-from` |
| `Install-FleetboardClient.ps1` | `C:\Program Files\Fleetboard\fleetboard-client.exe`, `%ProgramData%\Fleetboard\client.toml`, `%ProgramData%\Fleetboard\logs\`, the service `FleetboardClient` (LocalService), a firewall rule for 9280 from `-ServerIp` |

## Adding it to Erynne

Access → Remote → add an app: slug `fleetboard`, address `http://127.0.0.1:9281`, who may open it
= your IT group, no certificate, **Rewrite absolute links off**, shown in the window. Details and
the reasoning in [docs/MNEMERYNNE-SETUP.md](docs/MNEMERYNNE-SETUP.md).

## Temperature, disk-full and offline alerts in Wazuh

The server can turn hot machines into Wazuh alerts, with thresholds you choose per sensor and per
host, e.g. GPUs at 85 °C → level 7 and 95 °C → level 12, everything else at 80 °C → 5, 90 °C → 10.
Full disks (90 % → 7, 97 % → 12 by default) and hosts silent for 10 minutes (→ 10) are alerted
too, which covers machines without a Wazuh agent of their own.
Set them under `[wazuh]` in `server.toml`, point the box's Wazuh agent at the alert file, and add
[`deploy/wazuh/fleetboard_rules.xml`](deploy/wazuh/fleetboard_rules.xml) to the manager. Details in
[docs/WAZUH.md](docs/WAZUH.md).

## When something's wrong

| You see | It means | Do |
|---|---|---|
| `didn't answer in time` on a card | nothing reached the client's port | the client isn't running, or the firewall blocks 9280 from the Mnemerynne box: `install-client.sh --check` on that machine |
| `refused the connection` | the port is closed | the service is down: `journalctl -u fleetboard-client` / the Windows logs folder |
| `rejected the token` | the two tokens differ | put the same token in `client.toml` and `server.env`, restart both |
| `isn't a Fleetboard client` | something else answers on that port | wrong address or port |
| `is still warming up` | the client just started | wait two seconds |
| a blank frame in Erynne | the Remote app has rewriting on, or the address has a path | address `http://127.0.0.1:9281`, rewriting off |
| "You've been signed out of Mnemerynne" | the session ended while the stream was open | reload |
| no GPU block on a card | no collector found a card | `fleetboard-client once` on that machine and read the `NVIDIA:` / `AMD:` / `Windows counters:` log lines |
| `client too new (schema 2)` | a client was updated past the server | update the server |

## Developing

```bash
cargo test --all-targets && cargo clippy --all-targets -- -D warnings && cargo fmt --all -- --check
cargo run -p fleetboard-client -- once                       # one snapshot of this machine
cargo run -p fleetboard-client -- --config dev-client.toml run
cargo run -p fleetboard-server -- --config dev.toml run      # then open http://127.0.0.1:9281/
```

In debug builds the server reads `web/` from disk, so dashboard changes need no rebuild. More in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), the wire format in
[docs/WIRE-FORMAT.md](docs/WIRE-FORMAT.md), releases in [docs/CHANGELOG.md](docs/CHANGELOG.md).
