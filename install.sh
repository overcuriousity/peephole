#!/usr/bin/env bash
# peephole installer / upgrader (Debian/Ubuntu, x86_64):
#   curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash
#
# Re-running upgrades an existing installation. Environment overrides:
#   MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY, PEEPHOLE_DOMAIN, PEEPHOLE_TRUSTED_PROXIES  (first install)
#   PEEPHOLE_LOCAL_PROXY=1|0  a reverse proxy on this machine fronts the trap (first install);
#                      when 1, PEEPHOLE_TRUSTED_PROXIES is ignored and loopback is trusted instead
#   PEEPHOLE_TTY       read the wizard's answers from this file instead of the terminal (tests)
#   PEEPHOLE_ROLES     comma-separated subset of listener,scanner,web (asked when a terminal is
#                      present; all three when there is none)
#   PEEPHOLE_CLUSTER=1|0       take part in a cluster (a preset PEEPHOLE_CLUSTER_NAME implies 1)
#   PEEPHOLE_CLUSTER_NAME      this node's name in the cluster (first install)
#   PEEPHOLE_CLUSTER_LISTEN    RPC listener (the prompt offers 0.0.0.0:7443; required in an
#                              unattended cluster install)
#   PEEPHOLE_CLUSTER_ADVERTISE host:port peers dial (omit for an outbound-only node)
#   PEEPHOLE_JOIN_TOKEN        invite from an existing member; joined before the first start
#   PEEPHOLE_REMOTE_CONFIG=1|0 let holders of this node's config key change its settings (cluster only)
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

# Questions are read from the terminal, or from the file PEEPHOLE_TTY names
# (tests). One descriptor stays open so answers are consumed in order.
# Interactive only if it can actually be opened (in containers /dev/tty may
# exist without a terminal behind it).
TTY_IN="${PEEPHOLE_TTY:-/dev/tty}"
if { exec 3<"$TTY_IN"; } 2>/dev/null; then INTERACTIVE=1; else INTERACTIVE=0; fi
# Prompts go to the terminal; when answers come from a file, to stderr.
say() { if [ -z "${PEEPHOLE_TTY:-}" ] && [ "$INTERACTIVE" -eq 1 ]; then printf '%s' "$*" > /dev/tty; else printf '%s' "$*" >&2; fi; }

toml_safe() {
    if [[ "$1" == *[\"\\]* ]] || [[ "$1" == *$'\n'* ]]; then
        die "value contains characters that are not allowed (quote, backslash, newline): $1"
    fi
}

prompt() {
    # prompt <varname> <message> [default]: a required value.
    local var="$1" msg="$2" default="${3:-}" value=""
    if [ -n "${!var:-}" ]; then return 0; fi
    [ "$INTERACTIVE" -eq 1 ] || die "missing required setting: ${var} (set it as an environment variable for non-interactive installs)"
    if [ -n "$default" ]; then say "${msg} [${default}]: "; else say "${msg}: "; fi
    read -r value <&3 || true
    [ -n "$value" ] || value="$default"
    [ -n "$value" ] || die "no value provided for ${var}"
    toml_safe "$value"
    printf -v "$var" '%s' "$value"
}

# Like prompt, but an empty answer (or a non-interactive install without the
# variable) leaves it empty.
prompt_optional() {
    local var="$1" msg="$2" value=""
    if [ -n "${!var:-}" ] || [ "$INTERACTIVE" -ne 1 ]; then return 0; fi
    say "${msg} (empty to skip): "
    read -r value <&3 || true
    toml_safe "$value"
    printf -v "$var" '%s' "$value"
}

# ask_yn <varname> <question> <default y|n>: sets the variable to 1 or 0.
# A preset value (1/0/y/n/yes/no) is kept; without a terminal the default is
# taken.
ask_yn() {
    local var="$1" msg="$2" default="$3" value="${!1:-}"
    if [ -z "$value" ]; then
        if [ "$INTERACTIVE" -eq 1 ]; then
            if [ "$default" = y ]; then say "${msg} [Y/n]: "; else say "${msg} [y/N]: "; fi
            read -r value <&3 || true
        fi
        [ -n "$value" ] || value="$default"
    fi
    case "$value" in
        1|y|Y|yes|Yes|YES) printf -v "$var" '1' ;;
        0|n|N|no|No|NO) printf -v "$var" '0' ;;
        *) die "${var}: answer yes or no (got '${value}')" ;;
    esac
}

has_role() { [[ ",${PEEPHOLE_ROLES}," == *",$1,"* ]]; }

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

# --- questions (first install only; nothing is written before they are done) --
if [ "$upgrade" -ne 1 ]; then
    ROLE_TRAP=""; ROLE_SCANNER=""; ROLE_WEB=""
    if [ -z "${PEEPHOLE_ROLES:-}" ]; then
        if [ "$INTERACTIVE" -eq 1 ]; then
            say $'\nWhat should this node do? Any combination works; a cluster shares the work.\n'
            ask_yn ROLE_TRAP "Run a trap (catch and record requests that reach no real site)?" y
            ask_yn ROLE_SCANNER "Run the scanner (nmap counter-scans, from this machine's address)?" y
            ask_yn ROLE_WEB "Have the web interface (public wall of shame and admin area)?" y
            PEEPHOLE_ROLES=""
            [ "$ROLE_TRAP" = 1 ] && PEEPHOLE_ROLES="listener"
            [ "$ROLE_SCANNER" = 1 ] && PEEPHOLE_ROLES="${PEEPHOLE_ROLES:+$PEEPHOLE_ROLES,}scanner"
            [ "$ROLE_WEB" = 1 ] && PEEPHOLE_ROLES="${PEEPHOLE_ROLES:+$PEEPHOLE_ROLES,}web"
        else
            PEEPHOLE_ROLES="listener,scanner,web"
        fi
    fi
    PEEPHOLE_ROLES="$(printf '%s' "$PEEPHOLE_ROLES" | tr -d ' ')"
    for r in $(printf '%s' "$PEEPHOLE_ROLES" | tr ',' ' '); do
        case "$r" in listener|scanner|web) ;; *) die "unknown role '$r' in PEEPHOLE_ROLES (listener, scanner, web)";; esac
    done
    has_role listener || has_role scanner || has_role web || die "enable at least one of trap, scanner and web interface"
    TRAP_LISTEN="0.0.0.0:8080"
    if has_role listener; then
        ask_yn PEEPHOLE_LOCAL_PROXY "Is a reverse proxy on this machine (nginx) in front of the trap?" n
        if [ "$PEEPHOLE_LOCAL_PROXY" = 1 ]; then
            TRAP_LISTEN="127.0.0.1:8080"
            if [ -n "${PEEPHOLE_TRUSTED_PROXIES:-}" ] && [ "$PEEPHOLE_TRUSTED_PROXIES" != "127.0.0.1/32,::1/128" ]; then
                warn "PEEPHOLE_TRUSTED_PROXIES is ignored: with a proxy on this machine only loopback is trusted"
            fi
            PEEPHOLE_TRUSTED_PROXIES="127.0.0.1/32,::1/128"
        else
            prompt PEEPHOLE_TRUSTED_PROXIES "Trusted proxy CIDRs, comma-separated (X-Forwarded-For is trusted from these)" "10.0.0.0/8"
        fi
    fi
    if has_role web; then
        prompt PEEPHOLE_DOMAIN "Public domain of the admin dashboard (WebAuthn relying party)"
    fi
    # A preset node name means "yes" (unattended installs from before this
    # question existed).
    [ -n "${PEEPHOLE_CLUSTER_NAME:-}" ] && PEEPHOLE_CLUSTER="${PEEPHOLE_CLUSTER:-1}"
    if [ "$INTERACTIVE" -eq 1 ] && [ -z "${PEEPHOLE_CLUSTER:-}" ]; then
        say $'\nA cluster shares requests, the scan queue and results between nodes of different operators.\n'
    fi
    ask_yn PEEPHOLE_CLUSTER "Take part in a cluster (join one now or later, or start one)?" n
    if [ "$PEEPHOLE_CLUSTER" = 1 ]; then
        prompt PEEPHOLE_CLUSTER_NAME "This node's name (other operators see it in their admin area)"
        prompt PEEPHOLE_CLUSTER_LISTEN "Cluster RPC listener" "0.0.0.0:7443"
        prompt_optional PEEPHOLE_CLUSTER_ADVERTISE "Address other nodes dial (host:port; empty for an outbound-only node)"
        prompt_optional PEEPHOLE_JOIN_TOKEN "Invite token from a member (empty to start a new cluster or join later)"
        if [ "$INTERACTIVE" -eq 1 ] && [ -z "${PEEPHOLE_REMOTE_CONFIG:-}" ]; then
            say $'\nRemote configuration: this node gets a config key. Whoever you give it to can change\nthis node\'s scan pace, rescan cooldown and roles from their own node. You can rotate the key at any time.\n'
        fi
        ask_yn PEEPHOLE_REMOTE_CONFIG "Allow holders of this node's config key to change its settings?" n
        toml_safe "$PEEPHOLE_CLUSTER_NAME"; toml_safe "$PEEPHOLE_CLUSTER_LISTEN"
        toml_safe "${PEEPHOLE_CLUSTER_ADVERTISE:-}"; toml_safe "${PEEPHOLE_JOIN_TOKEN:-}"
    fi
    prompt_optional MAXMIND_ACCOUNT_ID "MaxMind GeoLite2 account ID (https://www.maxmind.com/en/accounts/current/license-key; optional: in a cluster the lookups of a member with credentials are shared, the databases are not)"
    if [ -n "${MAXMIND_ACCOUNT_ID:-}" ]; then
        prompt MAXMIND_LICENSE_KEY "MaxMind GeoLite2 license key"
    else
        warn "no MaxMind credentials: this node cannot look up GeoIP data; it shows what other cluster members look up, if any can"
    fi
    # Values that arrived preset from the environment were not checked by a prompt.
    toml_safe "${PEEPHOLE_DOMAIN:-}"; toml_safe "${PEEPHOLE_TRUSTED_PROXIES:-}"
    toml_safe "${PEEPHOLE_CLUSTER_NAME:-}"; toml_safe "${PEEPHOLE_CLUSTER_LISTEN:-}"; toml_safe "${PEEPHOLE_CLUSTER_ADVERTISE:-}"
    toml_safe "${MAXMIND_ACCOUNT_ID:-}"; toml_safe "${MAXMIND_LICENSE_KEY:-}"
fi
# The wizard is done (or was skipped on an upgrade); closing an fd that was never opened is harmless.
exec 3<&-

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

# --- configuration (first install only) --------------------------------------
CONFIG_KEY=""
if [ "$upgrade" -eq 1 ]; then
    info "Existing config at ${CONFIG_FILE} left untouched"
else
    info "Configuring peephole"
    proxies_toml="$(printf '%s' "${PEEPHOLE_TRUSTED_PROXIES:-}" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed '/^$/d' | sed 's/.*/"&"/' | paste -sd',' -)"
    role() { if has_role "$1"; then echo true; else echo false; fi; }
    # Written beside the download and checked first: a value the binary
    # rejects leaves no config behind, so a re-run asks again.
    new_config="${tmpdir}/config.toml"
    {
        echo "# peephole configuration — generated by install.sh"
        echo "# Full reference: https://github.com/${REPO}/blob/master/deploy/config.example.toml"
        if has_role listener; then
            echo
            echo "# Trap listener: your reverse proxy sends requests that match no real site here."
            echo "trap_listen = \"${TRAP_LISTEN}\""
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
retention_days = 90        # standalone only: delete older requests and scans; 0 = keep forever (ignored in a cluster)
# Non-global addresses (loopback, private, link-local, …) are never scanned.
never_scan = ["192.168.0.0/16"] # extra CIDRs this node's scanner never scans (own infra, monitoring)
CONFIG
        if [ "${PEEPHOLE_CLUSTER:-0}" = 1 ]; then
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
            if [ "$PEEPHOLE_REMOTE_CONFIG" = 1 ]; then
                echo "remote_config = true   # holders of this node's config key may change pace, cooldown and roles"
            else
                echo "remote_config = false  # only this node's admin interface, CLI and this file change its settings"
            fi
        fi
    } > "$new_config"
    "$INSTALL_BIN" check-config "$new_config" \
        || die "generated config failed validation; nothing was written to ${CONFIG_FILE}. Re-run the installer to answer again."
    install -m 0600 "$new_config" "$CONFIG_FILE"
    info "Wrote ${CONFIG_FILE} (mode 0600 — may contain your MaxMind license key)"
    # A reverse-proxy example that fits this node: only the roles it runs,
    # with its domain and listen addresses filled in.
    NGINX_EXAMPLE="${CONFIG_DIR}/nginx.example.conf"
    if has_role web || has_role listener; then
        {
            echo "# nginx in front of peephole — generated by install.sh for this node."
            echo "# Copy to /etc/nginx/sites-available/peephole, enable it and reload nginx;"
            echo "# install.sh printed the steps. peephole does not touch nginx itself."
            if has_role web; then
                echo "# Get the admin site's certificate first (certbot certonly --nginx), while"
                echo "# the distribution's default site still serves port 80."
            fi
            if has_role listener; then
                echo "# The catch-all trap below is the default_server for port 80. The"
                echo "# distribution's default site (/etc/nginx/sites-enabled/default) claims it"
                echo "# too, and nginx refuses two (\"duplicate default server\"): remove that site."
            fi
            if has_role web; then
                cat <<NGINX

# --- Admin area and wall of shame (TLS) --------------------------------------
server {
    # Works on every nginx; 1.25.1+ warns it is deprecated. There, "listen 443 ssl;"
    # plus "http2 on;" is the newer form.
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${PEEPHOLE_DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${PEEPHOLE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${PEEPHOLE_DOMAIN}/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Server-Sent Events for the live scan queue: no buffering, long timeout.
    location /admin/api/queue {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
    }

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name ${PEEPHOLE_DOMAIN};
    return 301 https://\$host\$request_uri;
}
NGINX
            fi
            if has_role listener; then
                trap_port="${TRAP_LISTEN##*:}"
                cat <<NGINX

# --- Catch-all trap ----------------------------------------------------------
# Every request for a host name no other server block claims lands here.
# X-Forwarded-For is set to the real peer address (never appended to what
# the client sent), and peephole trusts it only from the proxies in
# trusted_proxies.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:${trap_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
    }
}

# To also trap HTTPS probes, give the catch-all a self-signed certificate
# (scanners do not check it):
#   openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=localhost \\
#     -keyout /etc/ssl/private/peephole-trap.key -out /etc/ssl/certs/peephole-trap.crt
# server {
#     listen 443 ssl default_server;
#     listen [::]:443 ssl default_server;
#     server_name _;
#     ssl_certificate     /etc/ssl/certs/peephole-trap.crt;
#     ssl_certificate_key /etc/ssl/private/peephole-trap.key;
#     location / {
#         proxy_pass http://127.0.0.1:${trap_port};
#         proxy_http_version 1.1;
#         proxy_set_header Host \$host;
#         proxy_set_header X-Forwarded-For \$remote_addr;
#     }
# }
NGINX
                if [ "${PEEPHOLE_LOCAL_PROXY:-0}" != 1 ]; then
                    echo
                    echo "# Note: the trap listens on ${TRAP_LISTEN} and trusts X-Forwarded-For only from"
                    echo "# ${PEEPHOLE_TRUSTED_PROXIES}. For an nginx on this machine set"
                    echo "# trap_listen = \"127.0.0.1:8080\" and trusted_proxies = [\"127.0.0.1/32\", \"::1/128\"]."
                fi
            fi
        } > "$NGINX_EXAMPLE"
        chmod 0644 "$NGINX_EXAMPLE"
        info "Wrote ${NGINX_EXAMPLE} (reverse-proxy example for this node)"
    fi
    if [ "${PEEPHOLE_CLUSTER:-0}" = 1 ]; then
        info "Node key: $("$INSTALL_BIN" cluster id "$CONFIG_FILE" 2>/dev/null)"
        if [ -n "${PEEPHOLE_JOIN_TOKEN:-}" ]; then
            if "$INSTALL_BIN" cluster join "$PEEPHOLE_JOIN_TOKEN" "$CONFIG_FILE"; then
                info "Joined the cluster"
            else
                warn "joining the cluster failed; retry with: peephole cluster join <token>"
            fi
        fi
        if [ "$PEEPHOLE_REMOTE_CONFIG" = 1 ]; then
            CONFIG_KEY="$("$INSTALL_BIN" cluster config-key show "$CONFIG_FILE" 2>/dev/null || true)"
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

Next steps:
DONE
trap_listen="$(sed -n 's/^trap_listen *= *"\([^"]*\)".*/\1/p' "$CONFIG_FILE")"
if [ -e "${CONFIG_DIR}/nginx.example.conf" ]; then
    echo "  - Reverse proxy: an nginx example for this node is in ${CONFIG_DIR}/nginx.example.conf."
    echo "    With nginx installed, in this order:"
    if [ -n "$admin_listen" ]; then
        echo "      certbot certonly --nginx -d ${PEEPHOLE_DOMAIN:-<your-domain>}"
        echo "        (the admin site's certificate, while the default site still serves port 80)"
    fi
    if [ -n "$trap_listen" ]; then
        echo "      rm /etc/nginx/sites-enabled/default"
        echo "        (the distribution's default site also claims default_server, which the trap catch-all needs)"
    fi
    echo "      cp ${CONFIG_DIR}/nginx.example.conf /etc/nginx/sites-available/peephole"
    echo "      ln -s ../sites-available/peephole /etc/nginx/sites-enabled/peephole"
    echo "      nginx -t && systemctl reload nginx"
fi
if [ -n "$trap_listen" ]; then
    echo "  - Send requests that match no real site to the trap listener (${trap_listen}); see the nginx example."
fi
if grep -q '^\[cluster\]' "$CONFIG_FILE"; then
    echo "  - Cluster: open the RPC port to the other nodes only."
    echo "    Node key: $("$INSTALL_BIN" cluster id "$CONFIG_FILE" 2>/dev/null)"
    if grep -q '^advertise' "$CONFIG_FILE"; then
        echo "    Invite others with 'peephole cluster invite' (the invite is reusable; limit it with --uses or --ttl)."
    fi
    echo "    Join a cluster with 'peephole cluster join <token>'; leave with 'peephole cluster leave'."
    if [ -n "$CONFIG_KEY" ]; then
        echo "    Config key (give it only to operators who may change this node's pace, cooldown and roles):"
        echo "      $CONFIG_KEY"
        echo "    Withdraw it from everyone with 'peephole cluster config-key rotate'."
    elif grep -q '^remote_config = true' "$CONFIG_FILE"; then
        echo "    Config key: print it with 'peephole cluster config-key show' (give it only to operators"
        echo "    who may change this node's pace, cooldown and roles)."
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
