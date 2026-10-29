#!/usr/bin/env bash
# Install the Fleetboard server on the Mnemerynne box, as root.
#
#   install-server.sh --token TOKEN [--bind 127.0.0.1:9281] [--binary PATH|URL] [--version TAG] [--dry-run]
#   install-server.sh --check          # installed, running, answering?
#   install-server.sh --uninstall      # remove the service and binary (keeps the database and config)
#   install-server.sh --keep-options   # reinstall or update, keeping /etc/fleetboard/server.env
#
# It downloads the latest release binary (or takes --binary), verifies SHA256SUMS, writes the token to
# /etc/fleetboard/server.env (0640), creates the fleetboard user and /var/lib/fleetboard for the
# database, installs and starts the systemd unit. The server binds to 127.0.0.1 and is only ever
# reached through Mnemerynne's Remote proxy, so there is nothing to open in the firewall.
set -Eeuo pipefail

REPO="AELovelace/fleetboard"
NAME="fleetboard-server"
BIN="/usr/local/bin/$NAME"
CONF_DIR="/etc/fleetboard"
ENV_FILE="$CONF_DIR/server.env"
CONF="$CONF_DIR/server.toml"
UNIT="/etc/systemd/system/$NAME.service"
USER_NAME="fleetboard"
STATE="/var/lib/fleetboard"

TOKEN="" BIND="127.0.0.1:9281" BINARY="" VERSION="latest"
DRY=0 CHECK=0 UNINSTALL=0 KEEP=0

step() { printf '\n\033[1;35m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
sys()  { if [[ $DRY == 1 ]]; then note "would run: $*"; else "$@"; fi; }
put()  {
  local mode=$1 path=$2 tmp
  if [[ $DRY == 1 ]]; then note "would write $path (mode $mode)"; cat >/dev/null; return; fi
  tmp=$(mktemp "$path.XXXXXX"); cat >"$tmp"; chmod "$mode" "$tmp"; mv -f "$tmp" "$path"
}
usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case $1 in
    --token) TOKEN=$2; shift 2 ;;
    --bind) BIND=$2; shift 2 ;;
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

do_check() {
  step "Checking $NAME"
  [[ -x $BIN ]] && note "ok   binary $BIN ($($BIN --version 2>/dev/null))" || note "FAIL binary missing"
  [[ -f $ENV_FILE ]] && note "ok   token file $ENV_FILE" || note "FAIL $ENV_FILE missing"
  systemctl is-active --quiet "$NAME" && note "ok   service running" || note "FAIL service not running (journalctl -u $NAME)"
  local port=${BIND##*:}
  curl -fsS "http://127.0.0.1:$port/healthz" 2>/dev/null && echo || note "FAIL /healthz on $port"
}

do_uninstall() {
  step "Removing $NAME"
  sys systemctl disable --now "$NAME" 2>/dev/null || true
  sys rm -f "$UNIT" "$BIN"
  sys systemctl daemon-reload
  note "left in place: $ENV_FILE, $CONF and the database in $STATE"
}

fetch_binary() {
  step "Getting the binary"
  local asset="fleetboard-server-linux-x86_64" tmp; tmp=$(mktemp -d)
  if [[ -n $BINARY && -f $BINARY ]]; then note "using $BINARY"; cp "$BINARY" "$tmp/$asset"; else
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

make_user() {
  step "Service user $USER_NAME and $STATE"
  id "$USER_NAME" >/dev/null 2>&1 || sys useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
  sys mkdir -p "$STATE"
  sys chown "$USER_NAME:$USER_NAME" "$STATE"
  sys chmod 0750 "$STATE"
}

write_config() {
  step "Writing $ENV_FILE and $CONF"
  sys mkdir -p "$CONF_DIR"
  if [[ $KEEP == 1 && -f $ENV_FILE ]]; then note "keeping the existing token (--keep-options)"; else
    [[ -n $TOKEN ]] || die "--token is required (make one with: $BIN gen-token); or --keep-options"
    [[ ${#TOKEN} -ge 16 ]] || die "the token must be at least 16 characters"
    put 0640 "$ENV_FILE" <<EOF
# The shared token every Fleetboard client has. Read by the systemd unit; never in the toml.
FLEETBOARD_TOKEN=$TOKEN
EOF
    sys chown root:"$USER_NAME" "$ENV_FILE"
  fi
  put 0644 "$CONF" <<EOF
# Fleetboard server. The token lives in server.env (0640), not here.
bind = "$BIND"
db = "$STATE/fleetboard.db"
log = "info"
EOF
}

write_unit() {
  step "Writing $UNIT"
  put 0644 "$UNIT" <<EOF
[Unit]
Description=Fleetboard server ($BIND)
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
Group=$USER_NAME
# The token: FLEETBOARD_TOKEN in a root:fleetboard 0640 file.
EnvironmentFile=$ENV_FILE
ExecStart=$BIN --config $CONF run
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
# The database directory, created and owned for us.
StateDirectory=fleetboard
StateDirectoryMode=0750
# Hardening: it only needs the network and its state directory.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
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
  wait_healthy
  step "Done"
  note "now in Mnemerynne: Access → Remote → add slug 'fleetboard', address http://$BIND, your IT group, rewriting off"
}
main
