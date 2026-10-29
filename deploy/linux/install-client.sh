#!/usr/bin/env bash
# Install the Fleetboard client on a Linux box (Fedora/RHEL or Debian/Ubuntu), as root.
#
#   install-client.sh --token TOKEN [--bind 0.0.0.0:9280] [--name NAME] [--allow-from CIDR]
#                     [--binary PATH|URL] [--version TAG] [--dry-run]
#   install-client.sh --check          # is it installed, running and answering?
#   install-client.sh --uninstall      # remove the service, binary and config
#   install-client.sh --keep-options   # reinstall or update, keeping /etc/fleetboard/client.toml
#
# It downloads the latest release binary from GitHub (or takes --binary), verifies SHA256SUMS,
# writes /etc/fleetboard/client.toml, creates the fleetboard-client user, installs and starts the
# systemd unit, and opens port 9280 to the Mnemerynne box only (--allow-from, firewalld or ufw).
# --dry-run prints what it would do. Every function is small on purpose; read it top to bottom.
set -Eeuo pipefail

REPO="AELovelace/fleetboard"
NAME="fleetboard-client"
BIN="/usr/local/bin/$NAME"
CONF_DIR="/etc/fleetboard"
CONF="$CONF_DIR/client.toml"
UNIT="/etc/systemd/system/$NAME.service"
USER_NAME="fleetboard-client"
PORT=9280

TOKEN="" BIND="0.0.0.0:$PORT" DISPLAY_NAME="" ALLOW_FROM="" BINARY="" VERSION="latest"
DRY=0 CHECK=0 UNINSTALL=0 KEEP=0

step() { printf '\n\033[1;35m== %s\033[0m\n' "$*"; }            # a heading for each stage
note() { printf '   %s\n' "$*"; }                                # a line under it
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }               # stop with a reason
sys()  { if [[ $DRY == 1 ]]; then note "would run: $*"; else "$@"; fi; }   # run, or only say so
put()  {                                                          # put MODE PATH < content: write a file atomically
  local mode=$1 path=$2 tmp
  if [[ $DRY == 1 ]]; then note "would write $path (mode $mode)"; cat >/dev/null; return; fi
  tmp=$(mktemp "$path.XXXXXX"); cat >"$tmp"; chmod "$mode" "$tmp"; mv -f "$tmp" "$path"
}

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case $1 in
    --token) TOKEN=$2; shift 2 ;;
    --bind) BIND=$2; shift 2 ;;
    --name) DISPLAY_NAME=$2; shift 2 ;;
    --allow-from) ALLOW_FROM=$2; shift 2 ;;
    --binary) BINARY=$2; shift 2 ;;
    --version) VERSION=$2; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --check) CHECK=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --keep-options) KEEP=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown option $1 (try --help)" ;;
  esac
done

[[ $EUID -eq 0 || $DRY == 1 || $CHECK == 1 ]] || die "run as root (sudo)"

conf_value() { sed -n "s/^$1 = \"\(.*\)\"/\1/p" "$CONF" 2>/dev/null | head -1; }   # read one key from client.toml

do_check() {
  step "Checking $NAME"
  [[ -x $BIN ]] && note "ok   binary $BIN ($($BIN --version 2>/dev/null))" || note "FAIL binary $BIN missing"
  [[ -f $CONF ]] && note "ok   config $CONF" || note "FAIL config $CONF missing"
  systemctl is-active --quiet "$NAME" && note "ok   service running" || note "FAIL service not running (journalctl -u $NAME)"
  local port; port=$(conf_value bind); port=${port##*:}; port=${port:-$PORT}
  if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then note "ok   /healthz answers on $port"; else note "FAIL /healthz on $port"; fi
  if [[ -x $BIN && -f $CONF ]]; then
    note "sample: $(sudo -u "$USER_NAME" "$BIN" --config "$CONF" once 2>/dev/null | head -c 300 | tr '\n' ' ')…"
  fi
}

do_uninstall() {
  step "Removing $NAME"
  sys systemctl disable --now "$NAME" 2>/dev/null || true
  sys rm -f "$UNIT" "$BIN"
  sys systemctl daemon-reload
  note "left in place: $CONF (holds the token); delete it yourself if you mean it"
  if command -v firewall-cmd >/dev/null; then
    for rule in $(firewall-cmd --list-rich-rules 2>/dev/null | grep "port=\"$PORT\"" || true); do :; done
    note "firewalld: remove the rich rule for port $PORT by hand if one was added (firewall-cmd --list-rich-rules)"
  fi
}

fetch_binary() {
  step "Getting the binary"
  local asset="fleetboard-client-linux-x86_64" tmp
  tmp=$(mktemp -d)
  if [[ -n $BINARY && -f $BINARY ]]; then
    note "using $BINARY"; cp "$BINARY" "$tmp/$asset"
  else
    local base
    if [[ -n $BINARY ]]; then base=$BINARY
    elif [[ $VERSION == latest ]]; then base="https://github.com/$REPO/releases/latest/download"
    else base="https://github.com/$REPO/releases/download/$VERSION"; fi
    note "downloading $base/$asset"
    sys curl -fsSL -o "$tmp/$asset" "$base/$asset"
    sys curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
    if [[ $DRY == 0 ]]; then
      (cd "$tmp" && grep " $asset\$" SHA256SUMS | sha256sum -c -) || die "checksum of $asset doesn't match SHA256SUMS"
      note "checksum ok"
    fi
  fi
  sys install -m 0755 "$tmp/$asset" "$BIN"
  rm -rf "$tmp"
}

write_config() {
  step "Writing $CONF"
  if [[ $KEEP == 1 && -f $CONF ]]; then
    note "keeping the existing config (--keep-options)"
    return
  fi
  [[ -n $TOKEN ]] || die "--token is required (make one with: $BIN gen-token); or --keep-options to reuse the config"
  [[ ${#TOKEN} -ge 16 ]] || die "the token must be at least 16 characters"
  sys mkdir -p "$CONF_DIR"
  put 0640 "$CONF" <<EOF
# Fleetboard client. The token is shared with the server; bind is where it listens.
token = "$TOKEN"
bind = "$BIND"
name = "$DISPLAY_NAME"
gpu = true
log = "info"
EOF
  sys chown root:"$USER_NAME" "$CONF"
}

make_user() {
  step "Service user $USER_NAME"
  if id "$USER_NAME" >/dev/null 2>&1; then note "exists"; else
    sys useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
  fi
  # render + video: NVML opens /dev/nvidia*, and future collectors may open /dev/dri. amdgpu's
  # sysfs files are world-readable and need nothing.
  for g in render video; do
    if grep -q "^$g:" /etc/group 2>/dev/null; then sys usermod -aG "$g" "$USER_NAME"; else note "no group $g on this box; skipped"; fi
  done
}

write_unit() {
  step "Writing $UNIT"
  put 0644 "$UNIT" <<EOF
[Unit]
Description=Fleetboard client ($BIND)
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
Group=$USER_NAME
# render and video: /dev/nvidia* (NVML) and /dev/dri; amdgpu sysfs needs nothing extra.
SupplementaryGroups=render video
ExecStart=$BIN --config $CONF run
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
# Hardening. No PrivateDevices: it would hide /dev/nvidia* from NVML.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
  sys systemctl daemon-reload
  sys systemctl enable --now "$NAME"
}

open_firewall() {
  [[ -n $ALLOW_FROM ]] || { note "no --allow-from: the firewall is left alone (open $PORT to the Mnemerynne box yourself)"; return; }
  step "Firewall: $PORT from $ALLOW_FROM only"
  if command -v firewall-cmd >/dev/null; then
    sys firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ALLOW_FROM port port=$PORT protocol=tcp accept"
    sys firewall-cmd --reload
  elif command -v ufw >/dev/null; then
    sys ufw allow from "$ALLOW_FROM" to any port "$PORT" proto tcp
  else
    note "neither firewalld nor ufw found; open $PORT/tcp from $ALLOW_FROM yourself"
  fi
}

wait_healthy() {
  [[ $DRY == 0 ]] || return 0
  step "Waiting for /healthz"
  local port=${BIND##*:} i
  for i in $(seq 1 15); do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then note "answers: $(curl -fsS "http://127.0.0.1:$port/healthz")"; return; fi
    sleep 1
  done
  die "no answer on $port after 15 s; look at: journalctl -u $NAME -n 30"
}

main() {
  if [[ $CHECK == 1 ]]; then do_check; exit; fi
  if [[ $UNINSTALL == 1 ]]; then do_uninstall; exit; fi
  make_user
  fetch_binary
  write_config
  write_unit
  open_firewall
  wait_healthy
  step "Done"
  note "add this box in Fleetboard's Hosts tab as $(hostname -I 2>/dev/null | awk '{print $1}'):${BIND##*:}"
}
main
