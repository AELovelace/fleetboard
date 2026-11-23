# Temperature alerts in Wazuh

Fleetboard can raise a Wazuh alert when a machine runs hot. You choose which temperature is which
alert level, and you can give different sensors and hosts different thresholds.

```
fleetboard-server ──appends──> /var/log/fleetboard/wazuh-alerts.json ──> wazuh-agent ──> manager
  (checks every poll against          (one JSON line per change)        (localfile,     (fleetboard_rules.xml:
   [[wazuh.temperature]])                                                json format)     level = fleetboard.level)
```

## Turning it on

1. **Fleetboard server**: in `/etc/fleetboard/server.toml`, set `enabled = true` under `[wazuh]` and
   adjust the rules (below). Check the file with `fleetboard-server check-config`, then
   `systemctl restart fleetboard-server`. A new install writes a commented example; on an older
   install add the section yourself and re-run the installer once, without `--keep-options`, or add
   `LogsDirectory=fleetboard` to the unit, so that systemd creates `/var/log/fleetboard`.
2. **Wazuh agent on the same box**: add [`deploy/wazuh/ossec-agent.conf.xml`](../deploy/wazuh/ossec-agent.conf.xml)
   inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`, then `systemctl restart wazuh-agent`.
3. **Wazuh manager**: copy [`deploy/wazuh/fleetboard_rules.xml`](../deploy/wazuh/fleetboard_rules.xml)
   to `/var/ossec/etc/rules/`, then `systemctl restart wazuh-manager`. It uses rule ids
   100800–100815; renumber them if they clash with your own rules.

To test without a hot machine, temporarily add a rule with a low threshold (for example
`thresholds = [{ at_c = 20, level = 3 }]`), restart the server, and look for `rule.id 100803` in
the Wazuh dashboard. You can also check a line by hand with `/var/ossec/bin/wazuh-logtest` on the
manager.

## Setting the thresholds

```toml
[wazuh]
enabled = true
log = "/var/log/fleetboard/wazuh-alerts.json"
hysteresis_c = 3        # a level drops only once the sensor is this far below its threshold
repeat_minutes = 30     # send it again while a sensor stays hot (0 = only when the level changes)
recovered_level = 3     # level of the "back to normal" line (0 = don't send one)
max_log_mb = 50         # past this size the file moves to wazuh-alerts.json.1

[[wazuh.temperature]]
name = "NAS disks"
hosts = ["NAS"]                         # names from the Hosts tab, or hostnames
sensors = ["nvme", "drivetemp"]
thresholds = [ { at_c = 55, level = 7 }, { at_c = 65, level = 12 } ]

[[wazuh.temperature]]
name = "GPUs"
sensors = ["gpu"]
thresholds = [ { at_c = 85, level = 7 }, { at_c = 95, level = 12 } ]

[[wazuh.temperature]]
name = "Everything else"                # no sensors or hosts: matches everything left
thresholds = [ { at_c = 80, level = 5 }, { at_c = 90, level = 10 }, { at_c = 100, level = 12 } ]
```

- **The first matching rule decides.** Put specific rules first and a catch-all last. A
  temperature that no rule matches is ignored.
- **`sensors`** are pieces of the sensor's label in any case. Labels are whatever the client
  reports: on Linux the hwmon names such as `k10temp Tctl`, `coretemp Package id 0` or
  `nvme Composite`, and each GPU as `GPU <index> <name>`, for example `GPU 0 NVIDIA GeForce GTX 1050 Ti`.
  `fleetboard-client once` on a machine prints its labels. Windows usually reports no sensors
  apart from NVIDIA GPUs.
- **`thresholds`**: from `at_c` degrees up, the sensor is at Wazuh level `level` (1–15). Their
  order doesn't matter; the highest one reached applies.
- Leaving out `[[wazuh.temperature]]` entirely gives the defaults: any sensor, 80 °C → 5,
  90 °C → 10, 100 °C → 12.
- A misspelt key, a level outside 1–15 or two thresholds at the same temperature stop the server
  from starting, and `check-config` names the problem.

## What gets sent

A line is written only when something changes, so a sensor sitting at 86 °C doesn't fill the log:

| `state` | When | `level` |
|---|---|---|
| `raised` | the sensor reached a higher threshold (one line even if it jumped past several) | the new threshold's |
| `lowered` | it cooled below a threshold by `hysteresis_c`, but is still above a lower one | the lower threshold's |
| `ongoing` | still at the same level after `repeat_minutes` | the current one |
| `recovered` | it cooled below the lowest threshold by `hysteresis_c` | `recovered_level` |

```json
{"fleetboard":{"event":"temperature","state":"raised","level":10,"previous_level":5,"host":"RDS 1","address":"10.0.0.5:9280","hostname":"rds1","sensor":"k10temp Tctl","celsius":91.3,"threshold_c":90.0,"rule":"Everything else","message":"RDS 1 k10temp Tctl is 91.3 C (raised, rule Everything else)","ts":1762862400}}
```

Each line also appears in the server's journal (`Wazuh level 10 (raised): RDS 1 k10temp Tctl is
91.3 C (raised, rule Everything else)`). If the file can't be written, the journal says so once,
and again once writing works. The server remembers levels only in memory, so after a restart a
sensor that is still hot is reported again as `raised`.

## Disk-full and offline alerts

The same file also carries disk and offline lines, for machines that have no Wazuh agent of their
own. Their limits are Fleetboard's **thresholds** (in the database; see [API.md](API.md#thresholds),
changed with the API's *Set threshold* action), and their levels are set in `[wazuh]`:

```toml
[wazuh]
disk_level = 7             # a disk at disk_pct (default 90 %); 0 = no disk alerts
disk_critical_level = 12   # a disk at disk_critical_pct (default 97 %); 0 = stay at disk_level
disk_hysteresis_pct = 2    # a disk's level drops once it is this far below the limit
offline_level = 10         # a host silent for offline_minutes (default 10); 0 = no offline alerts
```

- **Disks** work like temperatures: `raised`, `lowered`, `ongoing` every `repeat_minutes`, and
  `recovered` at `recovered_level`. A disk that vanishes (an unplugged USB disk) is forgotten.
- **Offline**: `raised` once a host has failed every poll for `offline_minutes`, `ongoing` every
  `repeat_minutes`, `recovered` when it answers again. A paused host never raises one.

```json
{"fleetboard":{"event":"disk","state":"raised","level":7,"previous_level":0,"host":"rsync-box","address":"10.0.0.9:9280","hostname":"rsync","sensor":"/srv","used_pct":91.2,"threshold_pct":90.0,"rule":"disk","message":"rsync-box disk /srv is 91.2% full (raised)","ts":1762862400}}
{"fleetboard":{"event":"offline","state":"raised","level":10,"previous_level":0,"host":"NAS","address":"10.0.0.4:9280","hostname":"","sensor":"client","down_minutes":10,"error":"didn't answer in time","rule":"offline","message":"NAS hasn't answered for 10 min: didn't answer in time","ts":1762862400}}
```

The manager's rules ([`fleetboard_rules.xml`](../deploy/wazuh/fleetboard_rules.xml)) match all
three events and use `fleetboard.message` as the alert's description. **Copy the updated file to the
manager again** if you installed an older one; it matched temperature lines only.
