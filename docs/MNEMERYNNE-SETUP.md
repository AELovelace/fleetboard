# Putting Fleetboard inside Erynne

Fleetboard has no sign-in of its own. Mnemerynne's **Remote** feature proxies it at
`/remote/fleetboard/` behind Erynne's session and a group check, so the only thing to decide is
who may open it. Nothing in Mnemerynne needs changing; this is all settings.

## 1. Install on the Mnemerynne box

```bash
bash install-server.sh --token TOKEN                           # 127.0.0.1:9281
bash install-client.sh --token TOKEN --bind 127.0.0.1:9280     # the box watches itself over loopback
curl -s http://127.0.0.1:9281/healthz                          # {"status":"ok",…}
```

No firewall change: the server is loopback-only and the local client is polled over loopback.

## 2. Register the Remote app

**Access → Remote → Add**:

| Field | Value | Why |
|---|---|---|
| Slug | `fleetboard` | the URL becomes `/remote/fleetboard/` |
| Name | Fleetboard | shown on the Remote tab |
| Address on the network | `http://127.0.0.1:9281` | plain http on loopback; no path, no trailing slash |
| Who may open it | your IT / admins group | only they see server load; nobody else can reach the app at all |
| Certificate | none | loopback http |
| Rewrite absolute links in its pages | **off** | Fleetboard uses only relative URLs; rewriting would buffer and regex every page for nothing |
| Show it in the Remote window | on | it reads Erynne's theme from the parent frame when embedded |
| Enabled | on | |

Open **Remote → Fleetboard**. The page should paint at once with a "live" light in the top right.

## 3. Other machines

Each client's port 9280 should accept connections from the Mnemerynne box only. The installers do
this when told the server's address:

- Linux: `install-client.sh --allow-from <mnemerynne-ip>/32` (firewalld rich rule, or ufw)
- Windows: `Install-FleetboardClient.ps1 -ServerIp <mnemerynne-ip>` (a Windows Firewall rule
  scoped to that remote address and to the client's exe)

Then **Hosts** in the dashboard → name, address, **Check**, **Add**.

## 4. Group changes, sign-out and the stream

Mnemerynne checks the person's session and group when a request starts, which for a live stream
is once. Fleetboard therefore ends every stream after five minutes and the browser reconnects at
once, so a removed person loses the live view within five minutes and a signed-out one sees "You've
been signed out of Mnemerynne. Reload to sign in again." Group membership itself follows
Mnemerynne's AD snapshot (a few minutes).

## 5. If it doesn't show

| Symptom | Cause |
|---|---|
| a 502 "Fleetboard didn't answer" in the frame | the server isn't running on 9281: `install-server.sh --check` |
| a blank frame | rewriting is on, or the address has a path or trailing slash |
| it loads but every card says `didn't answer in time` | the clients' firewalls don't allow the Mnemerynne box (section 3) |
| it loads but the Hosts tab says `token: NOT SET` | `/etc/fleetboard/server.env` is missing `FLEETBOARD_TOKEN`; rerun `install-server.sh --token …` |
| the look doesn't match Erynne | normal when opened in a new tab (no parent frame); embedded it follows Erynne's theme |
