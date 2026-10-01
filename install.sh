#!/usr/bin/env bash
# peephole installer / upgrader (Debian/Ubuntu, x86_64):
#   curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash
#
# Re-running upgrades an existing installation. Environment overrides:
#   MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY, PEEPHOLE_DOMAIN, PEEPHOLE_TRUSTED_PROXIES  (first install)
#   PEEPHOLE_ROLES     comma-separated subset of listener,scanner,web (default: all three)
#   PEEPHOLE_CLUSTER_NAME      enables distributed mode with this node name (first install)
#   PEEPHOLE_CLUSTER_LISTEN    RPC listener (default 0.0.0.0:7443)
#   PEEPHOLE_CLUSTER_ADVERTISE host:port peers dial (omit for an outbound-only node)
#   PEEPHOLE_JOIN_TOKEN        invite from an existing member; joined before the first start
#   PEEPHOLE_FORCE=1   reinstall even when the installed version matches
#   BASE_URL           alternative download base (tests, mirrors)
#
# The whole script is one function called on the last line, so a truncated
# download executes nothing rather than half a script.
set -euo pipefail

# Pull the one-time setup token out of journal output. journalctl's default
# format prefixes every line with a timestamp/host/unit, so match the UUID
# itself rather than a column.
extract_token() {
    grep -A2 'enter this one-time token' \
        | grep -Eo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
        | head -1 || true
}
if [ "${1:-}" = "--extract-token" ]; then extract_token; exit 0; fi

main() {
REPO="overcuriousity/peephole"
ASSET="peephole-x86_64-unknown-linux-gnu"
BASE_URL="${BASE_URL:-https://github.com/${REPO}/releases/download/latest}"
INSTALL_BIN="/usr/local/bin/peephole"
CONFIG_DIR="/etc/peephole"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
DATA_DIR="/var/lib/peephole"
UNIT_FILE="/etc/systemd/system/peephole.service"
RULES_MANIFEST="${DATA_DIR}/.installed-rules.sha256"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- preconditions -----------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
command -v apt-get >/dev/null 2>&1 || die "this installer supports Debian/Ubuntu (apt) systems only"
command -v systemctl >/dev/null 2>&1 || die "systemd is required (systemctl not found)"
if [ "${PEEPHOLE_ALLOW_NO_SYSTEMD:-0}" != "1" ] && [ "$(cat /proc/1/comm 2>/dev/null)" != "systemd" ]; then
    die "systemd is not PID 1 (container or chroot?). The service cannot be managed here; set PEEPHOLE_ALLOW_NO_SYSTEMD=1 to install anyway."
fi
[ "$(uname -m)" = "x86_64" ] || die "only x86_64 builds are published; build from source on $(uname -m) (see README)"

# Interactive only if a terminal can actually be opened (in containers
# /dev/tty may exist without one).
if { exec 3</dev/tty; } 2>/dev/null; then INTERACTIVE=1; exec 3<&-; else INTERACTIVE=0; fi

prompt() {
    # prompt <varname> <message> [default]
    local var="$1" msg="$2" default="${3:-}" value
    if [ -n "${!var:-}" ]; then return 0; fi
    [ "$INTERACTIVE" -eq 1 ] || die "missing required setting: ${var} (set it as an environment variable for non-interactive installs)"
    if [ -n "$default" ]; then printf '%s [%s]: ' "$msg" "$default" > /dev/tty; else printf '%s: ' "$msg" > /dev/tty; fi
    read -r value < /dev/tty
    [ -n "$value" ] || value="$default"
    [ -n "$value" ] || die "no value provided for ${var}"
    printf -v "$var" '%s' "$value"
}

# Like prompt, but an empty answer (or a non-interactive install without the
# variable) leaves it empty.
prompt_optional() {
    local var="$1" msg="$2" value
    if [ -n "${!var:-}" ] || [ "$INTERACTIVE" -ne 1 ]; then return 0; fi
    printf '%s (empty to skip): ' "$msg" > /dev/tty
    read -r value < /dev/tty
    printf -v "$var" '%s' "$value"
}

has_role() { [[ ",${PEEPHOLE_ROLES}," == *",$1,"* ]]; }

toml_safe() {
    if [[ "$1" == *[\"\\]* ]] || [[ "$1" == *$'\n'* ]]; then
        die "value contains characters that are not allowed (quote, backslash, newline): $1"
    fi
}

# --- prerequisites (only what is missing) ------------------------------------
if [ "${PEEPHOLE_SKIP_APT:-0}" != "1" ]; then
    missing=()
    for pkg in nmap curl ca-certificates sqlite3; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        info "Installing prerequisites: ${missing[*]}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "${missing[@]}"
    fi
fi

# --- download + verify -------------------------------------------------------
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fetch() { curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors "$1" -o "$2"; }

info "Downloading latest peephole build"
fetch "${BASE_URL}/${ASSET}.tar.gz"        "${tmpdir}/${ASSET}.tar.gz"        || die "download failed (the rolling release may be mid-rebuild; retry in a minute)"
fetch "${BASE_URL}/${ASSET}.tar.gz.sha256" "${tmpdir}/${ASSET}.tar.gz.sha256" || die "checksum download failed"
info "Verifying checksum"
( cd "$tmpdir" && sha256sum -c --quiet "${ASSET}.tar.gz.sha256" ) || die "checksum mismatch"
tar -xzf "${tmpdir}/${ASSET}.tar.gz" -C "$tmpdir"
src="${tmpdir}/${ASSET}"

new_version="$(cut -d' ' -f1 "${src}/VERSION" 2>/dev/null || echo unknown)"
installed_version=""
if [ -x "$INSTALL_BIN" ]; then
    installed_version="$("$INSTALL_BIN" --version 2>/dev/null | awk '{print $2}' || true)"
fi
upgrade=0
[ -e "$CONFIG_FILE" ] && upgrade=1

if [ "$upgrade" -eq 1 ] && [ -n "$installed_version" ] && [ "$installed_version" = "$new_version" ] && [ "${PEEPHOLE_FORCE:-0}" != "1" ]; then
    info "peephole ${installed_version} is already up to date (set PEEPHOLE_FORCE=1 to reinstall)"
    exit 0
fi

# --- validate the new binary against the existing config before touching anything
if [ "$upgrade" -eq 1 ]; then
    info "Checking existing configuration with the new binary"
    if ! "${src}/peephole" check-config "$CONFIG_FILE"; then
        die "the new version rejects ${CONFIG_FILE}; nothing was changed. Fix the config and re-run."
    fi
fi

# --- install files -----------------------------------------------------------
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "${CONFIG_DIR}/rules"
info "Installing binary to ${INSTALL_BIN}"
install -m 0755 "${src}/peephole" "${INSTALL_BIN}.new"
if [ -x "$INSTALL_BIN" ]; then cp -p "$INSTALL_BIN" "${INSTALL_BIN}.prev"; fi
mv -f "${INSTALL_BIN}.new" "$INSTALL_BIN"

# Rules as conffiles: replace only files the operator has not edited.
info "Installing signature rules to ${CONFIG_DIR}/rules"
touch "$RULES_MANIFEST"
new_manifest="$(mktemp)"
for rule in "${src}/rules/"*.toml; do
    name="$(basename "$rule")"
    dest="${CONFIG_DIR}/rules/${name}"
    new_sum="$(sha256sum "$rule" | cut -d' ' -f1)"
    if [ ! -e "$dest" ]; then
        install -m 0644 "$rule" "$dest"
    else
        recorded="$(awk -v n="$name" '$2==n{print $1}' "$RULES_MANIFEST")"
        current="$(sha256sum "$dest" | cut -d' ' -f1)"
        if [ "$current" = "$new_sum" ]; then
            : # identical already
        elif [ -n "$recorded" ] && [ "$current" = "$recorded" ]; then
            install -m 0644 "$rule" "$dest"   # unedited → take upstream
        else
            install -m 0644 "$rule" "${dest}.new"
            warn "kept your edited ${dest}; new upstream version saved as ${dest}.new"
        fi
    fi
    printf '%s %s\n' "$new_sum" "$name" >> "$new_manifest"
done
mv -f "$new_manifest" "$RULES_MANIFEST"

install -m 0644 "${src}/deploy/nginx.example.conf" "${CONFIG_DIR}/nginx.example.conf"

# --- configuration (first install only) --------------------------------------
if [ "$upgrade" -eq 1 ]; then
    info "Existing config at ${CONFIG_FILE} left untouched"
else
    info "Configuring peephole"
    PEEPHOLE_ROLES="${PEEPHOLE_ROLES:-listener,scanner,web}"
    PEEPHOLE_ROLES="$(printf '%s' "$PEEPHOLE_ROLES" | tr -d ' ')"
    for r in $(printf '%s' "$PEEPHOLE_ROLES" | tr ',' ' '); do
        case "$r" in listener|scanner|web) ;; *) die "unknown role '$r' in PEEPHOLE_ROLES (listener, scanner, web)";; esac
    done
    prompt_optional MAXMIND_ACCOUNT_ID "MaxMind GeoLite2 account ID (https://www.maxmind.com/en/accounts/current/license-key; in a cluster one member with a key is enough)"
    if [ -n "${MAXMIND_ACCOUNT_ID:-}" ]; then
        prompt MAXMIND_LICENSE_KEY "MaxMind GeoLite2 license key"
    else
        warn "no MaxMind credentials: GeoIP enrichment is off unless a cluster member shares its databases"
    fi
    if has_role web; then
        prompt PEEPHOLE_DOMAIN "Public domain of the admin dashboard (WebAuthn relying party)"
        toml_safe "$PEEPHOLE_DOMAIN"
    fi
    if has_role listener; then
        prompt PEEPHOLE_TRUSTED_PROXIES "Trusted proxy CIDRs, comma-separated (X-Forwarded-For is trusted from these)" "10.0.0.0/8"
    fi
    prompt_optional PEEPHOLE_CLUSTER_NAME "Distributed mode: this node's name"
    if [ -n "${PEEPHOLE_CLUSTER_NAME:-}" ]; then
        prompt PEEPHOLE_CLUSTER_LISTEN "Cluster RPC listener" "0.0.0.0:7443"
        prompt_optional PEEPHOLE_CLUSTER_ADVERTISE "Address other nodes dial (host:port; empty for an outbound-only node)"
        toml_safe "$PEEPHOLE_CLUSTER_NAME"; toml_safe "$PEEPHOLE_CLUSTER_LISTEN"; toml_safe "${PEEPHOLE_CLUSTER_ADVERTISE:-}"
    fi
    toml_safe "${MAXMIND_ACCOUNT_ID:-}"; toml_safe "${MAXMIND_LICENSE_KEY:-}"
    proxies_toml="$(printf '%s' "${PEEPHOLE_TRUSTED_PROXIES:-}" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed '/^$/d' | sed 's/.*/"&"/' | paste -sd',' -)"
    role() { if has_role "$1"; then echo true; else echo false; fi; }
    {
        echo "# peephole configuration — generated by install.sh"
        echo "# Full reference: https://github.com/${REPO}/blob/master/deploy/config.example.toml"
        if has_role listener; then
            echo
            echo "# Trap listener: HAProxy routes fallback (nonexistent-route) traffic here directly."
            echo 'trap_listen = "0.0.0.0:8080"'
            echo "rules_dir = \"${CONFIG_DIR}/rules\""
            echo "# Proxies whose X-Forwarded-For header is trusted for the real client IP."
            echo "trusted_proxies = [${proxies_toml}]"
        fi
        if has_role web; then
            echo
            echo "# Admin listener: nginx terminates TLS in front of this (see nginx.example.conf)."
            echo 'admin_listen = "127.0.0.1:8443"'
        fi
        cat <<CONFIG

database_path = "${DATA_DIR}/peephole.db"
data_dir = "${DATA_DIR}"

[roles]
listener = $(role listener)
scanner = $(role scanner)
web = $(role web)
CONFIG
        if has_role web; then
            cat <<CONFIG

[webauthn]
rp_id = "${PEEPHOLE_DOMAIN}"
origin = "https://${PEEPHOLE_DOMAIN}"
rp_name = "peephole"
CONFIG
        fi
        if [ -n "${MAXMIND_ACCOUNT_ID:-}" ]; then
            cat <<CONFIG

[maxmind]
account_id = "${MAXMIND_ACCOUNT_ID}"
license_key = "${MAXMIND_LICENSE_KEY}"
CONFIG
        fi
        cat <<CONFIG

[scan]
max_workers = 2            # concurrent nmap subprocesses
timeout_secs = 1800        # per-scan wall-clock timeout (adjustable in the admin queue page)
rescan_cooldown_hours = 24 # per-IP rescan cooldown (one level upgrade allowed)
max_scans_per_hour = 30    # rate cap of this scanner; excess jobs stay queued
retention_days = 90        # delete requests and scan results older than this; 0 = keep forever
# Non-global addresses (loopback, private, link-local, …) are never scanned.
never_scan = ["192.168.0.0/16"] # extra CIDRs never counter-scanned (own infra, monitoring)
CONFIG
        if [ -n "${PEEPHOLE_CLUSTER_NAME:-}" ]; then
            cat <<CONFIG

[cluster]
node_name = "${PEEPHOLE_CLUSTER_NAME}"
listen = "${PEEPHOLE_CLUSTER_LISTEN}"
CONFIG
            if [ -n "${PEEPHOLE_CLUSTER_ADVERTISE:-}" ]; then
                echo "advertise = \"${PEEPHOLE_CLUSTER_ADVERTISE}\""
            else
                echo "# No advertise address: outbound-only (this node dials its peers)."
            fi
        fi
    } > "$CONFIG_FILE"
    chmod 0600 "$CONFIG_FILE"
    info "Wrote ${CONFIG_FILE} (mode 0600 — may contain your MaxMind license key)"
    "$INSTALL_BIN" check-config "$CONFIG_FILE" || die "generated config failed validation"
    if [ -n "${PEEPHOLE_CLUSTER_NAME:-}" ]; then
        info "Node key: $("$INSTALL_BIN" cluster id "$CONFIG_FILE" 2>/dev/null)"
        if [ -n "${PEEPHOLE_JOIN_TOKEN:-}" ]; then
            if "$INSTALL_BIN" cluster join "$PEEPHOLE_JOIN_TOKEN" "$CONFIG_FILE"; then
                info "Joined the cluster"
            else
                warn "joining the cluster failed; retry with: peephole cluster join <token>"
            fi
        fi
    fi
fi

# --- systemd -----------------------------------------------------------------
info "Installing systemd service"
install -m 0644 "${src}/deploy/peephole.service" "$UNIT_FILE"
systemctl daemon-reload
if systemctl is-enabled peephole >/dev/null 2>&1; then
    systemctl restart peephole; info "Restarted peephole service"
else
    systemctl enable --now peephole; info "Enabled and started peephole service"
fi

# --- health check with rollback ----------------------------------------------
admin_listen="$(sed -n 's/^admin_listen *= *"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -1)"
if [ "${PEEPHOLE_SKIP_HEALTH:-0}" != "1" ]; then
    healthy=0
    if [ -n "$admin_listen" ]; then
        info "Waiting for http://${admin_listen}/healthz"
        for _ in $(seq 1 20); do
            if curl -fs "http://${admin_listen}/healthz" >/dev/null 2>&1; then healthy=1; break; fi
            sleep 1
        done
    else
        # No web role, so no HTTP endpoint: the service must stay up.
        info "Waiting for the service to stay up (no web role, no /healthz)"
        sleep 5
        if systemctl is-active --quiet peephole; then healthy=1; fi
    fi
    if [ "$healthy" -ne 1 ]; then
        journalctl -u peephole -n 30 --no-pager >&2 || true
        if [ -x "${INSTALL_BIN}.prev" ] && [ "$upgrade" -eq 1 ]; then
            warn "new version did not become healthy; rolling back to the previous binary"
            mv -f "${INSTALL_BIN}.prev" "$INSTALL_BIN"
            systemctl restart peephole
            die "rolled back. The log above shows why the new version failed."
        fi
        die "peephole did not become healthy; see the log above"
    fi
fi

# --- done --------------------------------------------------------------------
if [ "$upgrade" -eq 1 ]; then
    info "Upgraded peephole ${installed_version:-?} → ${new_version}"
    exit 0
fi

token=""
if [ "${PEEPHOLE_SKIP_HEALTH:-0}" != "1" ]; then
    token="$(journalctl -u peephole --since '-2min' --no-pager -o cat 2>/dev/null | extract_token)"
fi
cat <<DONE

peephole ${new_version} is installed and running.

  service status : systemctl status peephole
  logs           : journalctl -u peephole -f
  config         : ${CONFIG_FILE}
  nginx example  : ${CONFIG_DIR}/nginx.example.conf  (SSE needs proxy_buffering off — see file)

Next steps:
DONE
if [ -n "$(sed -n 's/^trap_listen *= *"\([^"]*\)".*/\1/p' "$CONFIG_FILE")" ]; then
    echo "  - Route fallback traffic from HAProxy to the trap listener (0.0.0.0:8080)."
fi
if grep -q '^\[cluster\]' "$CONFIG_FILE"; then
    echo "  - Distributed mode: open the cluster RPC port to the other nodes only."
    echo "    Node key: $("$INSTALL_BIN" cluster id "$CONFIG_FILE" 2>/dev/null)"
    if grep -q '^advertise' "$CONFIG_FILE"; then
        echo "    Add members with 'peephole cluster invite' here and 'peephole cluster join <token>' there."
    else
        echo "    Outbound-only: join a reachable member with 'peephole cluster join <token>' (invite created there)."
    fi
fi
if [ -n "$admin_listen" ]; then
    echo "  - Terminate TLS with nginx in front of the admin listener (${admin_listen}) using the example config."
    echo "  - Enroll your first FIDO2 admin key at https://${PEEPHOLE_DOMAIN:-<your-domain>}/enroll"
    if [ -n "$token" ]; then
        printf '    one-time setup token: %s\n' "$token"
    else
        printf '    the one-time setup token is in the service log: journalctl -u peephole | grep -A2 token\n'
    fi
fi
}

main "$@"
