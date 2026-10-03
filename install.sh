#!/usr/bin/env bash
# peephole installer / upgrader (Debian/Ubuntu, x86_64 or aarch64):
#   curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash
# A pinned release, with the installer from the same tag:
#   curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/v0.1.1/install.sh | sudo PEEPHOLE_VERSION=v0.1.1 bash
#
# Re-running upgrades an existing installation. Environment overrides:
#   PEEPHOLE_VERSION   release tag to install (e.g. v0.1.0); default: the rolling "latest" build of master
#   PEEPHOLE_VERIFY=1|0  1: require a verified GitHub build provenance attestation (needs the gh CLI);
#                      0: skip it; unset: verify when gh is installed, warn if that fails
#   MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY, PEEPHOLE_DOMAIN, PEEPHOLE_TRUSTED_PROXIES  (first install)
#   ABUSEIPDB_API_KEY, SHODAN_API_KEY, GREYNOISE_API_KEY  optional enrichment APIs (first install)
#   PEEPHOLE_INTERNETDB=1|0    use Shodan InternetDB, no key, non-commercial use only (first
#                              install; asked with default yes, off without a terminal)
#   PEEPHOLE_FRONT=direct|local|remote  what is in front of the trap (first install):
#                      direct: nothing, the trap takes ports 80 and 443 itself (no proxy trusted);
#                      local: nginx on this machine (loopback trusted, PEEPHOLE_TRUSTED_PROXIES
#                      ignored); remote: a proxy on another machine (PEEPHOLE_TRUSTED_PROXIES
#                      required). Default: remote when PEEPHOLE_TRUSTED_PROXIES is set, local with
#                      the web role or when 80/443 are taken, direct otherwise
#   PEEPHOLE_LOCAL_PROXY=1|0  older form of PEEPHOLE_FRONT: 1 is local, 0 is remote
#   PEEPHOLE_OWN_ADDRESSES  public addresses no interface shows (1:1 NAT), comma-separated, for
#                      [scan] own_addresses; default: what the cloud metadata reports, "-" for none
#   PEEPHOLE_METADATA=1|0  ask the cloud's metadata service for the public address (default 1)
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
#   PEEPHOLE_NGINX=1|0 install and configure nginx (and, with the web role, a Let's Encrypt
#                      certificate via certbot) after peephole is up (first install; default 0;
#                      offered for the web role and for a trap behind a local proxy)
#   PEEPHOLE_ACME_EMAIL        contact address for Let's Encrypt (optional; with PEEPHOLE_NGINX=1)
#   PEEPHOLE_FORCE=1   reinstall even when the installed version matches
#   BASE_URL           alternative download base (tests, mirrors)
#
# Other entry points: --extract-token (reads journal output on stdin),
# --nginx-example and --nginx-stream-example (print the nginx site and the
# top-level stream config for PEEPHOLE_ROLES, PEEPHOLE_DOMAIN and
# PEEPHOLE_FRONT=local|remote; deploy/nginx.example.conf and
# deploy/nginx-stream.example.conf are their output for a full node).
#
# The whole script is one function called on the last line, so a truncated
# download executes nothing rather than half a script. With PEEPHOLE_NO_MAIN=1
# sourcing it only defines the helpers above main (tests/deploy-check.sh).
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

has_role() { [[ ",${PEEPHOLE_ROLES}," == *",$1,"* ]]; }

# Whether nginx on this machine takes port 443 at the TCP level and passes
# TLS for unknown names through to the trap (which reads the handshake
# itself): a trap behind a local proxy.
stream_trap() { has_role listener && [ "${PEEPHOLE_LOCAL_PROXY:-0}" = 1 ]; }

# --- what the machine has (questions; top level so tests can source them) ---

# Whether a TCP socket listens on <host> <port>, read from /proc/net/tcp and
# tcp6: minimal systems (the ubuntu container) have no ss. A wildcard on
# either side clashes, as does [::] with an IPv4 address; an IPv6 address
# other than [::] is taken to clash with anything on the port. The kernel
# prints an IPv4 address as a host-order word: little endian on x86_64 and
# aarch64, the machines this installer supports. PEEPHOLE_PROC_NET: tests.
port_in_use() {
    local host="${1#[}" port="$2" dir="${PEEPHOLE_PROC_NET:-/proc/net}" want="" hexport f files=()
    host="${host%]}"
    printf -v hexport '%04X' "$port"
    if [[ "$host" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] && [ "$host" != 0.0.0.0 ]; then
        printf -v want '%02X%02X%02X%02X' "${BASH_REMATCH[4]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}"
    fi
    for f in "$dir/tcp" "$dir/tcp6"; do [ -r "$f" ] && files+=("$f"); done
    [ "${#files[@]}" -gt 0 ] || return 1
    # Column 2 is the local address:port, column 4 the state (0A: LISTEN).
    awk -v port="$hexport" -v want="$want" '
        $4 == "0A" {
            split($2, la, ":")
            if (la[2] != port) next
            if (want == "" || la[1] == want || la[1] ~ /^0+$/ || la[1] == "0000000000000000FFFF0000" want) { found = 1; exit }
        }
        END { exit !found }' "${files[@]}"
}

# Who holds a port, as "nginx (pid 123)", when ss is there to say.
port_holder() {
    command -v ss >/dev/null 2>&1 || return 0
    ss -Htlnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)",pid=\([0-9]*\).*/\1 (pid \2)/p' | head -1
}

valid_ipv4() {
    local IFS=. o
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    for o in $1; do [ "$((10#$o))" -le 255 ] || return 1; done
}
valid_ip() { valid_ipv4 "$1" || { [[ "$1" == *:* ]] && [[ "$1" =~ ^[0-9A-Fa-f:.]+$ ]]; }; }

# Not loopback, private, CGNAT or link-local.
public_ipv4() {
    valid_ipv4 "$1" || return 1
    case "$1" in
        0.*|10.*|127.*|169.254.*|192.168.*) return 1 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
    esac
}

# The big cloud this machine runs on, from its DMI data (empty elsewhere).
# Their acceptable use policies forbid scanning others.
cloud_from_dmi() {
    local dir="${1:-/sys/class/dmi/id}" vendor product bios tag
    vendor="$(cat "$dir/sys_vendor" 2>/dev/null || true)"
    product="$(cat "$dir/product_name" 2>/dev/null || true)"
    bios="$(cat "$dir/bios_vendor" 2>/dev/null || true)"
    tag="$(cat "$dir/chassis_asset_tag" 2>/dev/null || true)"
    if [[ "$vendor" == Amazon* || "$bios" == Amazon* ]]; then echo "Amazon Web Services"
    elif [[ "$vendor" == Google* || "$product" == "Google Compute Engine" ]]; then echo "Google Cloud"
    # Hyper-V on a desk says the same but for the asset tag.
    elif [ "$vendor" = "Microsoft Corporation" ] && [ "$product" = "Virtual Machine" ] \
            && [ "$tag" = 7783-7084-3265-9085-8269-3286-77 ]; then echo "Microsoft Azure"
    elif [[ "$vendor $product" == *Alibaba* ]]; then echo "Alibaba Cloud"
    elif [ "$tag" = OracleCloud.com ]; then echo "Oracle Cloud"
    fi
}

# "<provider> <address>": this machine's public IPv4 address from its
# cloud's metadata service, nothing when there is none. One second per
# question at most, no proxy, no echo service outside the provider.
cloud_public_ip() {
    local md=(curl -fs --noproxy '*' --connect-timeout 1 --max-time 1) ip token
    # Every service below answers at 169.254.169.254 (GCP's name too):
    # nothing there, nothing to ask.
    curl -s --noproxy '*' --connect-timeout 1 --max-time 1 -o /dev/null http://169.254.169.254/ || return 0
    token="$("${md[@]}" -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token || true)"
    if [ -n "$token" ]; then
        ip="$("${md[@]}" -H "X-aws-ec2-metadata-token: ${token}" http://169.254.169.254/latest/meta-data/public-ipv4 || true)"
        valid_ipv4 "$ip" && { echo "aws $ip"; return 0; }
    fi
    ip="$("${md[@]}" -H 'Metadata-Flavor: Google' \
        http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip || true)"
    valid_ipv4 "$ip" && { echo "gcp $ip"; return 0; }
    ip="$("${md[@]}" -H 'Metadata: true' \
        'http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text' || true)"
    valid_ipv4 "$ip" && { echo "azure $ip"; return 0; }
    ip="$("${md[@]}" http://169.254.169.254/hetzner/v1/metadata/public-ipv4 || true)"
    valid_ipv4 "$ip" && { echo "hetzner $ip"; return 0; }
    ip="$("${md[@]}" http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address || true)"
    valid_ipv4 "$ip" && { echo "digitalocean $ip"; return 0; }
    return 0
}

# The addresses of this machine's interfaces, one per line.
local_addresses() {
    if command -v ip >/dev/null 2>&1; then
        ip -o addr show 2>/dev/null | awk '{ sub(/\/.*/, "", $4); print $4 }'
    elif [ -r "${PEEPHOLE_PROC_NET:-/proc/net}/fib_trie" ]; then
        # IPv4 only: "|-- <address>" followed by "/32 host LOCAL".
        awk '/\|--/ { a = $2 } /\/32 host LOCAL/ { print a }' "${PEEPHOLE_PROC_NET:-/proc/net}/fib_trie" | sort -u
    else
        hostname -I 2>/dev/null | tr ' ' '\n' | sed '/^$/d'
    fi
}

# A comma-separated list as the inside of a TOML array: "a","b".
toml_list() { printf '%s' "$1" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed '/^$/d' | sed 's/.*/"&"/' | paste -sd',' -; }

# The top-level nginx stream config for this node, on stdout (nothing when
# nginx does not front the trap's TLS). It goes into nginx.conf's main
# context, outside http {}: install.sh writes it to
# /etc/nginx/peephole-stream.conf and includes it there.
nginx_stream_example() {
    stream_trap || return 0
    local tls_port="${TRAP_TLS_LISTEN##*:}"
    echo "# nginx stream config for peephole, generated by install.sh for a node with the"
    echo "# roles ${PEEPHOLE_ROLES//,/, }. It belongs in nginx.conf's main context (outside"
    echo "# http {}): install.sh writes it to /etc/nginx/peephole-stream.conf and adds"
    echo "# \"include /etc/nginx/peephole-stream.conf;\" to /etc/nginx/nginx.conf. Needs the"
    echo "# stream module (Debian/Ubuntu: libnginx-mod-stream)."
    echo "#"
    echo "# Port 443 is routed by server name without decrypting (ssl_preread). The"
    echo "# trap reads the TLS handshake itself (JA4 fingerprint, raw ClientHello) and"
    echo "# learns the client's address from the PROXY protocol header."
    echo "#"
    echo "# Other HTTPS sites on this nginx must move behind it too: add a line"
    echo "# \"<their name> 127.0.0.1:8444;\" to the map and change their \"listen 443 ssl\""
    echo "# to \"listen 127.0.0.1:8444 ssl proxy_protocol;\" plus \"set_real_ip_from"
    echo "# 127.0.0.1; real_ip_header proxy_protocol;\" (as the admin site has)."
    if has_role web; then
        cat <<NGINX
stream {
    map \$ssl_preread_server_name \$peephole_upstream {
        ${PEEPHOLE_DOMAIN} 127.0.0.1:8444;
        default 127.0.0.1:${tls_port};
    }
    server {
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_pass \$peephole_upstream;
        proxy_protocol on;
    }
}
NGINX
    else
        cat <<NGINX
stream {
    server {
        listen 443;
        listen [::]:443;
        proxy_pass 127.0.0.1:${tls_port};
        proxy_protocol on;
    }
}
NGINX
    fi
}

# The nginx example that fits this node, on stdout: only the roles it runs,
# with its domain and listen addresses filled in. Reads PEEPHOLE_ROLES,
# PEEPHOLE_DOMAIN, TRAP_LISTEN, ADMIN_LISTEN, PEEPHOLE_LOCAL_PROXY and
# PEEPHOLE_TRUSTED_PROXIES. deploy/nginx.example.conf is this output for a
# full node behind a local nginx; tests/deploy-check.sh keeps the two equal.
nginx_example() {
    local trap_port="${TRAP_LISTEN##*:}"
    echo "# nginx in front of peephole, generated by install.sh for a node with the"
    echo "# roles ${PEEPHOLE_ROLES//,/, }."
    echo "# Copy to /etc/nginx/sites-available/peephole, enable it and reload nginx;"
    echo "# install.sh prints the steps, or does them when asked to (PEEPHOLE_NGINX=1)."
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

# Login and first-key enrollment are rate limited per client address.
# limit_req_zone belongs to the http context, where sites-enabled/ is included.
limit_req_zone \$binary_remote_addr zone=peephole_auth:10m rate=30r/m;

# --- Admin area and wall of shame (TLS) --------------------------------------
server {
NGINX
        if stream_trap; then
            cat <<NGINX
    # Port 443 belongs to the stream config (peephole-stream.conf), which
    # hands this domain's connections here with a PROXY protocol header.
    # Works on every nginx; 1.25.1+ warns it is deprecated. There,
    # "listen ... ssl proxy_protocol;" plus "http2 on;" is the newer form.
    listen 127.0.0.1:8444 ssl http2 proxy_protocol;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
NGINX
        else
            cat <<NGINX
    # Works on every nginx; 1.25.1+ warns it is deprecated. There, "listen 443 ssl;"
    # plus "http2 on;" is the newer form.
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
NGINX
        fi
        cat <<NGINX
    server_name ${PEEPHOLE_DOMAIN};
    server_tokens off;

    ssl_certificate     /etc/letsencrypt/live/${PEEPHOLE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${PEEPHOLE_DOMAIN}/privkey.pem;

    # HSTS (the app also sets it; harmless to set here too).
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Server-Sent Events for the live scan queue: no buffering, long timeout.
    location /admin/api/queue {
        proxy_pass http://${ADMIN_LISTEN};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        # proxy_buffering off is what actually disables buffering here; the
        # X-Accel-Buffering response header is for the upstream to send.
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
    }

    # FIDO2 login and enrollment (the first key needs a one-time token).
    location ~ ^/(login|enroll)(/|\$) {
        limit_req zone=peephole_auth burst=20 nodelay;
        limit_req_status 429;
        proxy_pass http://${ADMIN_LISTEN};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        proxy_pass http://${ADMIN_LISTEN};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name ${PEEPHOLE_DOMAIN};
    server_tokens off;
    return 301 https://\$host\$request_uri;
}
NGINX
        if ! stream_trap; then
            cat <<'NGINX'

# --- Every other name on 443 -------------------------------------------------
# Without a default_server for 443, nginx answers every TLS connection with
# the admin site: HTTPS scanners would land there instead of in the trap, and
# its certificate would tell them the admin domain. This refuses the TLS
# handshake for any name not served above (needs nginx >= 1.19.4).
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
NGINX
        fi
    fi
    if has_role listener; then
        cat <<NGINX

# --- Catch-all trap ----------------------------------------------------------
# Every request for a host name no other server block claims lands here.
# X-Forwarded-For is set to the real peer address (never appended to what
# the client sent), and peephole trusts it only from the proxies in
# trusted_proxies. Host is passed on exactly as the client sent it.
# The trap caps connections per client (64), but behind this proxy it sees
# only nginx: the same cap is applied here, so one client cannot hold every
# upstream connection. limit_conn_zone belongs to the http context too.
limit_conn_zone \$binary_remote_addr zone=peephole_trap:10m;

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;
    # Bodies up to 1 MiB reach the trap, which keeps the first 64 KiB; nginx
    # would otherwise refuse them with 413 and nothing would be recorded.
    client_max_body_size 1m;
    limit_conn peephole_trap 64;
    limit_conn_status 429;

    location / {
        proxy_pass http://127.0.0.1:${trap_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-For \$remote_addr;
    }
}
NGINX
        if stream_trap; then
            echo
            echo "# HTTPS: port 443 is in the stream config (peephole-stream.conf), which passes"
            echo "# TLS for every name but the admin domain through to the trap's TLS listener."
        fi
        if [ "${PEEPHOLE_LOCAL_PROXY:-0}" != 1 ]; then
            echo
            echo "# Note: the trap listens on ${TRAP_LISTEN} and trusts X-Forwarded-For only from"
            echo "# ${PEEPHOLE_TRUSTED_PROXIES}. For an nginx on this machine set"
            echo "# trap_listen = \"127.0.0.1:8080\" and trusted_proxies = [\"127.0.0.1/32\", \"::1/128\"]."
            echo "# HTTPS: the trap's TLS listener (${TRAP_TLS_LISTEN}) terminates TLS itself; your"
            echo "# proxy forwards port 443 untouched (TCP) and sends a PROXY protocol header."
        fi
    fi
}

if [ "${1:-}" = "--nginx-example" ] || [ "${1:-}" = "--nginx-stream-example" ]; then
    PEEPHOLE_ROLES="${PEEPHOLE_ROLES:-listener,scanner,web}"
    PEEPHOLE_DOMAIN="${PEEPHOLE_DOMAIN:-peephole.example.net}"
    ADMIN_LISTEN="127.0.0.1:8443"
    # A trap that takes 80/443 itself (direct) has nothing for nginx to front.
    case "${PEEPHOLE_FRONT:-}" in
        local) PEEPHOLE_LOCAL_PROXY=1 ;;
        remote) PEEPHOLE_LOCAL_PROXY=0 ;;
        "") ;;
        *) echo "PEEPHOLE_FRONT: local or remote for the nginx examples (got '${PEEPHOLE_FRONT}')" >&2; exit 1 ;;
    esac
    if [ "${PEEPHOLE_LOCAL_PROXY:-1}" = 1 ]; then
        PEEPHOLE_LOCAL_PROXY=1; TRAP_LISTEN="127.0.0.1:8080"; TRAP_TLS_LISTEN="127.0.0.1:8081"
    else
        TRAP_LISTEN="0.0.0.0:8080"; TRAP_TLS_LISTEN="0.0.0.0:8081"
        PEEPHOLE_TRUSTED_PROXIES="${PEEPHOLE_TRUSTED_PROXIES:-the address of your proxy}"
    fi
    if [ "$1" = "--nginx-stream-example" ]; then nginx_stream_example; else nginx_example; fi
    exit 0
fi

main() {
REPO="overcuriousity/peephole"
case "$(uname -m)" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) ARCH="" ;;
esac
ASSET="peephole-${ARCH:-unsupported}-unknown-linux-gnu"
# A release tag pins the download; the default is the rolling build of master.
RELEASE="${PEEPHOLE_VERSION:-latest}"
BASE_URL="${BASE_URL:-https://github.com/${REPO}/releases/download/${RELEASE}}"
INSTALL_BIN="/usr/local/bin/peephole"
CONFIG_DIR="/etc/peephole"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
DATA_DIR="/var/lib/peephole"
UNIT_FILE="/etc/systemd/system/peephole.service"
# Written by installers that put the signature rules in ${CONFIG_DIR}/rules;
# the rules are built into the binary now. Its presence means the operator
# has not been told yet.
OLD_RULES_MANIFEST="${DATA_DIR}/.installed-rules.sha256"
UNIT_MANIFEST="${DATA_DIR}/.installed-unit.sha256"
# Units earlier installers wrote without recording them: unedited if they match.
KNOWN_UNIT_SUMS="da20ef8147a9f2a9e704318e80ce381adc7b222fc5b21706bc1f5fd3bd4c5cb2 38da8e128f109b566c222e2b5a44ff486893981057371225ddf1bd7e1d4aa8ae"

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
[ -n "$ARCH" ] || die "builds are published for x86_64 and aarch64 only; build from source on $(uname -m) (see docs/operations.md)"
if [ "$RELEASE" != latest ] && ! [[ "$RELEASE" =~ ^v[0-9]+(\.[0-9]+)*(-[0-9A-Za-z.]+)?$ ]]; then
    die "PEEPHOLE_VERSION must be a release tag such as v0.1.0 (got '${RELEASE}')"
fi

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

# claim_port <varname> <what> <offer 1|0> [hint]: the host:port in the
# variable must be free, and not taken by another listener of the new config.
# If it is not, an interactive install is offered the next free port (when
# <offer> is 1); otherwise the install stops before anything is written. A
# value that is no host:port is left to check-config.
CLAIMED_PORTS=" "
claim_port() {
    local var="$1" what="$2" offer="$3" hint="${4:-}" value="${!1}" host port next holder msg reply=""
    port="${value##*:}"; host="${value%:*}"
    { [[ "$port" =~ ^[0-9]{1,5}$ ]] && [ "$host" != "$value" ] && [ "$port" -le 65535 ]; } || return 0
    port_taken() { port_in_use "$host" "$1" || [[ "$CLAIMED_PORTS" == *" $1 "* ]]; }
    if ! port_taken "$port"; then CLAIMED_PORTS+="${port} "; return 0; fi
    if [[ "$CLAIMED_PORTS" == *" $port "* ]]; then holder="another listener of this node"; else holder="$(port_holder "$port")"; fi
    msg="port ${port} for the ${what} (${value}) is in use${holder:+ by ${holder}}"
    if [ "$INTERACTIVE" -eq 1 ] && [ "$offer" = 1 ]; then
        next=$((port + 1))
        while [ "$next" -le 65535 ] && port_taken "$next"; do next=$((next + 1)); done
        [ "$next" -le 65535 ] || die "$msg"
        say "${msg}."$'\n'
        ask_yn reply "Use ${host}:${next} instead?" y
        [ "$reply" = 1 ] || die "${msg}; free it and run the installer again"
        printf -v "$var" '%s' "${host}:${next}"
        CLAIMED_PORTS+="${next} "
        return 0
    fi
    die "${msg}; free it and run the installer again${hint}"
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

# --retry-all-errors needs curl 7.71; older ones refuse the option.
retry_all=()
if curl --help all 2>/dev/null | grep -q -- --retry-all-errors; then retry_all=(--retry-all-errors); fi
fetch() { curl -fsSL --retry 5 --retry-delay 3 ${retry_all[@]+"${retry_all[@]}"} "$1" -o "$2"; }

download() {
    fetch "${BASE_URL}/${ASSET}.tar.gz"        "${tmpdir}/${ASSET}.tar.gz"        || die "download of ${BASE_URL}/${ASSET}.tar.gz failed (no such release, or the rolling release is mid-update; retry in a minute)"
    fetch "${BASE_URL}/${ASSET}.tar.gz.sha256" "${tmpdir}/${ASSET}.tar.gz.sha256" || die "checksum download failed"
}
checksum_ok() { ( cd "$tmpdir" && sha256sum -c --quiet "${ASSET}.tar.gz.sha256" ); }

info "Downloading peephole ${RELEASE} (${ARCH})"
download
info "Verifying checksum"
if ! checksum_ok; then
    # The rolling release replaces its files one at a time, so a download in
    # between can get a tarball and a checksum of different builds.
    warn "checksum mismatch; the release may be mid-update, downloading again in 15 s"
    sleep 15
    download
    checksum_ok || die "checksum mismatch"
fi

# Provenance: a GitHub attestation that this repository's workflow built the
# tarball (the checksum alone only shows the download is intact).
verify="${PEEPHOLE_VERIFY:-}"
if [ "$verify" != 0 ]; then
    if command -v gh >/dev/null 2>&1; then
        info "Verifying the build provenance attestation"
        bundle=()
        # Releases carry the attestation bundle, so no GitHub API call is needed.
        if curl -fsSL "${BASE_URL}/peephole-provenance.sigstore.json" -o "${tmpdir}/provenance.json" 2>/dev/null; then
            bundle=(--bundle "${tmpdir}/provenance.json")
        fi
        if gh attestation verify "${tmpdir}/${ASSET}.tar.gz" --repo "$REPO" "${bundle[@]}" > "${tmpdir}/attestation.log" 2>&1; then
            info "Provenance verified: built by a GitHub Actions workflow of ${REPO}"
        elif [ "$verify" = 1 ]; then
            cat "${tmpdir}/attestation.log" >&2
            die "the provenance attestation did not verify (PEEPHOLE_VERIFY=1)"
        else
            warn "could not verify the provenance attestation (gh may need 'gh auth login'); relying on the checksum. PEEPHOLE_VERIFY=1 makes this fatal."
        fi
    elif [ "$verify" = 1 ]; then
        die "PEEPHOLE_VERIFY=1 needs the GitHub CLI (gh) to verify the provenance attestation"
    fi
fi

tar -xzf "${tmpdir}/${ASSET}.tar.gz" -C "$tmpdir"
src="${tmpdir}/${ASSET}"

# VERSION: "<build> <date> <commit>" (older builds have no commit).
new_version="unknown"; build_date=""; build_commit=""
if [ -r "${src}/VERSION" ]; then read -r new_version build_date build_commit < "${src}/VERSION" || true; fi
[ -n "$new_version" ] || new_version="unknown"
info "Build ${new_version} of ${build_date:-unknown date}, from commit ${build_commit:-unknown}"
# This script and the binary may come from different commits (the script
# from master, the binary from a release). The build ships its own copy.
if [ -n "$build_commit" ] && [ -f "${src}/install.sh" ]; then
    self="${BASH_SOURCE[0]:-}"
    if [ -n "$self" ] && [ -f "$self" ] && cmp -s "$self" "${src}/install.sh"; then
        info "This installer is the one shipped with the build"
    else
        info "The installer shipped with this build: https://raw.githubusercontent.com/${REPO}/${build_commit}/install.sh"
        if [ -n "$self" ] && [ -f "$self" ]; then
            warn "this installer differs from the one shipped with the build"
        fi
    fi
fi
installed_version=""
if [ -x "$INSTALL_BIN" ]; then
    installed_version="$("$INSTALL_BIN" --version 2>/dev/null | awk '{print $2}' || true)"
fi
upgrade=0
[ -e "$CONFIG_FILE" ] && upgrade=1

# Unless it is not running (say, a first install that failed to start):
# then go on and start it.
if [ "$upgrade" -eq 1 ] && [ -n "$installed_version" ] && [ "$installed_version" = "$new_version" ] && [ "${PEEPHOLE_FORCE:-0}" != "1" ]; then
    if systemctl is-active --quiet peephole; then
        info "peephole ${installed_version} is already up to date (set PEEPHOLE_FORCE=1 to reinstall)"
        exit 0
    fi
    info "peephole ${installed_version} is installed but not running; installing again"
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
    # Where this runs. A big cloud forbids scanning others; behind 1:1 NAT
    # (most clouds) no interface carries the public address, which only the
    # metadata service knows.
    CLOUD="$(cloud_from_dmi)"
    md_provider=""; md_addr=""
    if [ "${PEEPHOLE_METADATA:-1}" = 1 ] && { [ -z "${PEEPHOLE_ROLES:-}" ] || has_role listener || has_role scanner; }; then
        read -r md_provider md_addr <<<"$(cloud_public_ip)" || true
    fi
    case "$md_provider" in
        aws) CLOUD="${CLOUD:-Amazon Web Services}" ;;
        gcp) CLOUD="${CLOUD:-Google Cloud}" ;;
        azure) CLOUD="${CLOUD:-Microsoft Azure}" ;;
    esac
    if_addrs="$(local_addresses)"
    # The public address: one an interface carries, else the metadata's.
    PUBLIC_ADDR=""
    for a in $if_addrs; do public_ipv4 "$a" && { PUBLIC_ADDR="$a"; break; }; done
    DETECTED_OWN=""
    if [ -n "$md_addr" ] && ! printf '%s\n' "$if_addrs" | grep -qxF "$md_addr"; then
        DETECTED_OWN="$md_addr"
        PUBLIC_ADDR="${PUBLIC_ADDR:-$md_addr}"
    fi
    cloud_warning="This machine runs on ${CLOUD}. Its acceptable use policy forbids scanning other people's machines, and counter-scans draw abuse reports that risk suspension of the account."

    ROLE_TRAP=""; ROLE_SCANNER=""; ROLE_WEB=""
    if [ -z "${PEEPHOLE_ROLES:-}" ]; then
        if [ "$INTERACTIVE" -eq 1 ]; then
            say $'\nWhat should this node do? Any combination works; a cluster shares the work.\n'
            ask_yn ROLE_TRAP "Run a trap (catch and record requests that reach no real site)?" y
            if [ -n "$CLOUD" ]; then
                say "${cloud_warning} Run the scanner elsewhere (another node of a cluster)."$'\n'
            fi
            ask_yn ROLE_SCANNER "Run the scanner (nmap counter-scans, from this machine's address)?" "$([ -n "$CLOUD" ] && echo n || echo y)"
            say $'The web interface needs a domain whose DNS points here, and HTTPS (WebAuthn). Without one answer no: in a cluster the admin area of another node shows everything.\n'
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
    # Without the question (preset roles, no terminal), the warning still.
    if [ -n "$CLOUD" ] && has_role scanner && [ -z "$ROLE_SCANNER" ]; then warn "$cloud_warning"; fi
    TRAP_LISTEN="0.0.0.0:8080"
    TRAP_TLS_LISTEN="0.0.0.0:8081"
    ADMIN_LISTEN="127.0.0.1:8443"
    if has_role listener; then
        # What is in front of the trap. PEEPHOLE_LOCAL_PROXY is the yes/no
        # form of this question that earlier installers asked.
        if [ -z "${PEEPHOLE_FRONT:-}" ] && [ -n "${PEEPHOLE_LOCAL_PROXY:-}" ]; then
            ask_yn PEEPHOLE_LOCAL_PROXY "" n
            if [ "$PEEPHOLE_LOCAL_PROXY" = 1 ]; then PEEPHOLE_FRONT=local; else PEEPHOLE_FRONT=remote; fi
        fi
        busy=""
        for p in 80 443; do
            if port_in_use 0.0.0.0 "$p"; then
                holder="$(port_holder "$p")"
                busy="${busy:+$busy, }port ${p}${holder:+ (${holder})}"
            fi
        done
        # The default: preset trusted proxies mean a proxy elsewhere (what
        # unattended installs from before this question got). The web role
        # needs port 443 for the admin site, so nginx shares it by name.
        if [ -n "${PEEPHOLE_TRUSTED_PROXIES:-}" ]; then front_default=remote
        elif has_role web || [ -n "$busy" ]; then front_default=local
        else front_default=direct
        fi
        while :; do
            front="${PEEPHOLE_FRONT:-}"
            if [ -z "$front" ]; then
                if [ "$INTERACTIVE" -eq 1 ]; then
                    say $'\nWhat is in front of the trap?\n  direct  nothing: the trap takes ports 80 and 443 itself\n  local   nginx on this machine (it keeps 80/443 and hands the trap what no real site claims)\n  remote  a proxy or load balancer on another machine\n'
                    say "direct, local or remote [${front_default}]: "
                    read -r front <&3 || true
                fi
                front="${front:-$front_default}"
            fi
            problem=""
            case "$front" in
                direct)
                    if has_role web; then
                        problem="direct needs port 443 for the trap, and the admin site needs it too. Choose local: nginx on this machine splits port 443 by name (the admin domain to the admin site, every other name to the trap; the installer can set it up). Or run the web interface on another node of a cluster."
                    elif [ -n "$busy" ]; then
                        problem="direct needs ports 80 and 443, but ${busy} is in use here. Choose local to put the trap behind the nginx that holds it, or free the ports."
                    fi ;;
                local|remote) ;;
                *) problem="answer direct, local or remote (got '${front}')" ;;
            esac
            [ -z "$problem" ] && break
            # A preset answer, or one without a terminal, is not asked again.
            if [ -n "${PEEPHOLE_FRONT:-}" ] || [ "$INTERACTIVE" -ne 1 ]; then die "PEEPHOLE_FRONT=${front}: ${problem}"; fi
            say "${problem}"$'\n'
            front_default=local
        done
        PEEPHOLE_FRONT="$front"
        PEEPHOLE_LOCAL_PROXY=0
        case "$front" in
            direct)
                TRAP_LISTEN="0.0.0.0:80"
                TRAP_TLS_LISTEN="0.0.0.0:443"
                if [ -n "${PEEPHOLE_TRUSTED_PROXIES:-}" ]; then
                    warn "PEEPHOLE_TRUSTED_PROXIES is ignored: nothing is in front of the trap, so no proxy is trusted"
                fi
                PEEPHOLE_TRUSTED_PROXIES="" ;;
            local)
                PEEPHOLE_LOCAL_PROXY=1
                TRAP_LISTEN="127.0.0.1:8080"
                TRAP_TLS_LISTEN="127.0.0.1:8081"
                if [ -n "${PEEPHOLE_TRUSTED_PROXIES:-}" ] && [ "$PEEPHOLE_TRUSTED_PROXIES" != "127.0.0.1/32,::1/128" ]; then
                    warn "PEEPHOLE_TRUSTED_PROXIES is ignored: with a proxy on this machine only loopback is trusted"
                fi
                PEEPHOLE_TRUSTED_PROXIES="127.0.0.1/32,::1/128" ;;
            remote)
                if [ "$INTERACTIVE" -eq 1 ] && [ -z "${PEEPHOLE_TRUSTED_PROXIES:-}" ]; then
                    say $'The proxy sends plain HTTP that matches no real site to the trap (port 8080) and passes TLS\nfor unknown names untouched, with a PROXY protocol v2 header, to the TLS trap (port 8081).\nHosts in these ranges are believed about the client address: list only the proxy.\n'
                fi
                prompt PEEPHOLE_TRUSTED_PROXIES "Address(es) of that proxy, as seen from this machine (CIDRs, comma-separated)"
                # A bare address is that one host.
                proxies=""
                for a in $(printf '%s' "$PEEPHOLE_TRUSTED_PROXIES" | tr ',' ' '); do
                    if [[ "$a" != */* ]] && valid_ip "$a"; then
                        if [[ "$a" == *:* ]]; then a="${a}/128"; else a="${a}/32"; fi
                    fi
                    proxies="${proxies:+$proxies,}${a}"
                done
                PEEPHOLE_TRUSTED_PROXIES="$proxies" ;;
        esac
        # 80/443 for direct were checked above: no other port to offer.
        offer=1; [ "$front" = direct ] && offer=0
        claim_port TRAP_LISTEN "trap listener" "$offer"
        claim_port TRAP_TLS_LISTEN "TLS trap listener" "$offer"
    else
        # No trap, nothing in front of it (a preset answer is moot).
        PEEPHOLE_FRONT=""
    fi
    # Addresses the scanner must know as its own (never scanned, never in
    # the blocklist): requests the host makes to its own trap through 1:1
    # NAT arrive from them.
    OWN_ADDRESSES=""
    if has_role listener || has_role scanner; then
        OWN_ADDRESSES="${PEEPHOLE_OWN_ADDRESSES:-$DETECTED_OWN}"
        if [ -z "${PEEPHOLE_OWN_ADDRESSES:-}" ] && [ -n "$DETECTED_OWN" ] && [ "$INTERACTIVE" -eq 1 ]; then
            say $'\n'"The ${md_provider} metadata gives this machine the public address ${DETECTED_OWN}, which no interface shows (1:1 NAT)."$'\n'
            say "Public addresses of this machine that its interfaces do not show (comma-separated; - for none) [${DETECTED_OWN}]: "
            answer=""
            read -r answer <&3 || true
            OWN_ADDRESSES="${answer:-$DETECTED_OWN}"
        fi
        [ "$OWN_ADDRESSES" = - ] && OWN_ADDRESSES=""
        OWN_ADDRESSES="$(printf '%s' "$OWN_ADDRESSES" | tr -d ' ')"
        toml_safe "$OWN_ADDRESSES"
        for a in $(printf '%s' "$OWN_ADDRESSES" | tr ',' ' '); do
            valid_ip "$a" || die "PEEPHOLE_OWN_ADDRESSES: '${a}' is not an IP address"
        done
        if [ -n "$OWN_ADDRESSES" ]; then
            info "Public address not on an interface: ${OWN_ADDRESSES} (goes into [scan] own_addresses)"
        fi
    fi
    if has_role web; then
        prompt PEEPHOLE_DOMAIN "Public domain of the admin dashboard (WebAuthn relying party)"
        claim_port ADMIN_LISTEN "admin listener" 1
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
        claim_port PEEPHOLE_CLUSTER_LISTEN "cluster RPC listener" 1 "; or set PEEPHOLE_CLUSTER_LISTEN to another address"
        advertise_example="host:port"
        [ -n "$PUBLIC_ADDR" ] && advertise_example="host:port, e.g. ${PUBLIC_ADDR}:${PEEPHOLE_CLUSTER_LISTEN##*:}"
        prompt_optional PEEPHOLE_CLUSTER_ADVERTISE "Address other nodes dial (${advertise_example}; empty: outbound-only, this node dials its peers, which works)"
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
    if [ "$INTERACTIVE" -eq 1 ]; then
        say $'\nOptional threat-intel APIs. Every one is optional: leave it empty to skip it. Keys stay on this\nnode; in a cluster the lookup results are shared, so one key serves every member.\n'
    fi
    prompt_optional ABUSEIPDB_API_KEY "AbuseIPDB API key (https://www.abuseipdb.com/account/api; abuse reports per IP, free plan 1000 checks/day)"
    prompt_optional SHODAN_API_KEY "Shodan API key (https://account.shodan.io; open ports, services and CVEs; host lookups need a membership or paid plan)"
    prompt_optional GREYNOISE_API_KEY "GreyNoise Community API key (https://viz.greynoise.io/account/api-key; mass-scanner or benign; free keys need a business email, 50 lookups/week)"
    ask_yn PEEPHOLE_INTERNETDB "Use Shodan InternetDB (no key; ports, tags and CVEs, weekly data; free for non-commercial use only)?" "$([ "$INTERACTIVE" -eq 1 ] && echo y || echo n)"
    # nginx is set up only where it fronts something peephole serves: the
    # admin site, or a trap behind nginx on this machine (local). Not for a
    # trap that takes 80/443 itself (direct, never with the web role) or
    # one behind a proxy elsewhere (remote).
    nginx_fits=0
    if has_role listener; then
        [ "$PEEPHOLE_FRONT" = local ] && nginx_fits=1
    elif has_role web; then
        nginx_fits=1
    fi
    if [ "$nginx_fits" = 1 ]; then
        if [ "$INTERACTIVE" -eq 1 ] && [ -z "${PEEPHOLE_NGINX:-}" ]; then
            if has_role web; then
                say $'
nginx: the installer can install nginx and certbot, get a Let\'s Encrypt certificate for
the admin domain (its DNS must point here and port 80 must be reachable), enable the site and
reload nginx. Otherwise it prints the steps at the end.
'
            else
                say $'
nginx: the installer can install nginx, enable the trap catch-all (it replaces the
distribution\'s default site) and reload nginx. Otherwise it prints the steps at the end.
'
            fi
        fi
        ask_yn PEEPHOLE_NGINX "Install and configure nginx for peephole now?" n
        if [ "$PEEPHOLE_NGINX" = 1 ] && has_role web; then
            prompt_optional PEEPHOLE_ACME_EMAIL "Contact email for Let's Encrypt (expiry notices)"
        fi
    elif [ "${PEEPHOLE_NGINX:-0}" = 1 ]; then
        die "PEEPHOLE_NGINX=1 needs the web role or a trap behind nginx on this machine (PEEPHOLE_FRONT=local); set up your proxy by hand"
    else
        PEEPHOLE_NGINX=0
    fi
    # Values that arrived preset from the environment were not checked by a prompt.
    toml_safe "${PEEPHOLE_DOMAIN:-}"; toml_safe "${PEEPHOLE_TRUSTED_PROXIES:-}"
    toml_safe "${PEEPHOLE_CLUSTER_NAME:-}"; toml_safe "${PEEPHOLE_CLUSTER_LISTEN:-}"; toml_safe "${PEEPHOLE_CLUSTER_ADVERTISE:-}"
    toml_safe "${MAXMIND_ACCOUNT_ID:-}"; toml_safe "${MAXMIND_LICENSE_KEY:-}"
    toml_safe "${ABUSEIPDB_API_KEY:-}"; toml_safe "${SHODAN_API_KEY:-}"; toml_safe "${GREYNOISE_API_KEY:-}"
    if [ -n "${PEEPHOLE_ACME_EMAIL:-}" ] && ! [[ "$PEEPHOLE_ACME_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]]; then
        die "PEEPHOLE_ACME_EMAIL is not an email address: ${PEEPHOLE_ACME_EMAIL}"
    fi
fi
# The wizard is done (or was skipped on an upgrade); closing an fd that was never opened is harmless.
exec 3<&-

# --- backups for a rollback (upgrades) ----------------------------------------
# The binary is kept as peephole.prev; the unit and its manifest beside the
# download (for this run's rollback); the database next to itself.
backup="${tmpdir}/rollback"
mkdir -p "$backup"
DB_PATH="${DATA_DIR}/peephole.db"
DB_BACKUP=""
DB_SCHEMA=""
schema_version() { sqlite3 "$1" 'PRAGMA user_version' 2>/dev/null || true; }
backup_database() {
    local need avail dest
    [ -e "$DB_PATH" ] || return 0
    if ! command -v sqlite3 >/dev/null 2>&1; then
        warn "sqlite3 is not installed; upgrading without a database backup"
        return 0
    fi
    # The WAL file may not exist (du then fails but still prints the total).
    need="$(du -ck "$DB_PATH" "${DB_PATH}-wal" 2>/dev/null | tail -1 | cut -f1 || true)"
    avail="$(df -Pk "$(dirname "$DB_PATH")" | awk 'NR==2 {print $4}')"
    if [ "${avail:-0}" -le "$(( ${need:-0} + 1024 ))" ]; then
        warn "not enough free space for a copy of ${DB_PATH}; upgrading without a database backup"
        return 0
    fi
    dest="$(dirname "$DB_PATH")/backup-$(date -u +%Y%m%dT%H%M%SZ).db"
    info "Backing up the database to ${dest}"
    # The online backup API: consistent while the running service writes.
    if ( umask 077; sqlite3 "$DB_PATH" ".backup '${dest}'" ); then
        DB_BACKUP="$dest"
        DB_SCHEMA="$(schema_version "$dest")"
        # Keep the two newest backups (the names sort by time).
        find "$(dirname "$DB_PATH")" -maxdepth 1 -name 'backup-*.db' | sort -r | tail -n +3 | xargs -r rm -f --
    else
        rm -f "$dest"
        warn "the database backup failed; upgrading without one"
    fi
}
if [ "$upgrade" -eq 1 ]; then
    configured_db="$(sed -n 's/^database_path *= *"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -1)"
    DB_PATH="${configured_db:-$DB_PATH}"
    if [ -e "$UNIT_FILE" ]; then cp -p "$UNIT_FILE" "${backup}/peephole.service"; fi
    if [ -e "$UNIT_MANIFEST" ]; then cp -p "$UNIT_MANIFEST" "${backup}/unit.sha256"; fi
    backup_database
fi

# --- install files -----------------------------------------------------------
# The config holds the MaxMind key, the data dir the node key and the
# database: readable by root only.
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chmod 0750 "$CONFIG_DIR"
chmod 0700 "$DATA_DIR"
for f in "$DB_PATH" "${DB_PATH}-wal" "${DB_PATH}-shm"; do
    if [ -e "$f" ]; then chmod 0600 "$f"; fi
done
info "Installing binary to ${INSTALL_BIN}"
install -m 0755 "${src}/peephole" "${INSTALL_BIN}.new"
if [ -x "$INSTALL_BIN" ]; then cp -p "$INSTALL_BIN" "${INSTALL_BIN}.prev"; fi
mv -f "${INSTALL_BIN}.new" "$INSTALL_BIN"

# The annotated reference for this version (not read by peephole).
install -m 0644 "${src}/deploy/config.example.toml" "${CONFIG_DIR}/config.example.toml"

# --- configuration (first install only) --------------------------------------
CONFIG_KEY=""
if [ "$upgrade" -eq 1 ]; then
    info "Existing config at ${CONFIG_FILE} left untouched"
else
    info "Configuring peephole"
    proxies_toml="$(toml_list "${PEEPHOLE_TRUSTED_PROXIES:-}")"
    role() { if has_role "$1"; then echo true; else echo false; fi; }
    # Written beside the download and checked first: a value the binary
    # rejects leaves no config behind, so a re-run asks again.
    new_config="${tmpdir}/config.toml"
    {
        echo "# peephole configuration — generated by install.sh"
        echo "# Annotated reference for the installed version: ${CONFIG_DIR}/config.example.toml"
        if has_role listener; then
            echo
            if [ "${PEEPHOLE_FRONT:-}" = direct ]; then
                echo "# Trap listener: nothing in front of it, it takes the public HTTP port itself."
                echo "trap_listen = \"${TRAP_LISTEN}\""
                echo "# TLS trap listener on the public HTTPS port: peephole terminates TLS itself"
                echo "# and keeps the handshake (JA4)."
                echo "trap_tls_listen = \"${TRAP_TLS_LISTEN}\""
                echo "# No proxy in front: X-Forwarded-For is never believed."
            else
                echo "# Trap listener: your reverse proxy sends requests that match no real site here."
                echo "trap_listen = \"${TRAP_LISTEN}\""
                echo "# TLS trap listener: peephole terminates TLS itself and keeps the handshake"
                echo "# (JA4). Your proxy forwards TLS to it untouched, with a PROXY protocol header."
                echo "trap_tls_listen = \"${TRAP_TLS_LISTEN}\""
                echo "# Proxies whose X-Forwarded-For header is trusted for the real client IP."
            fi
            echo "trusted_proxies = [${proxies_toml}]"
        fi
        if has_role web; then
            echo
            echo "# Admin listener: nginx terminates TLS in front of this (see nginx.example.conf)."
            echo "admin_listen = \"${ADMIN_LISTEN}\""
        fi
        cat <<CONFIG

database_path = "${DATA_DIR}/peephole.db"
data_dir = "${DATA_DIR}"
# Keep records and history of the last N days on this node only (at least 7);
# 0 = keep everything. In a cluster, other nodes keep theirs.
retention_days = 0

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

[enrichment]
# API providers look an IP up once; when it comes back, again after N days,
# then 1.5 N, 2.25 N, … since the last lookup. 0 = never again.
refresh_after_days = 30
CONFIG
        if [ -n "${ABUSEIPDB_API_KEY:-}" ]; then
            cat <<CONFIG

[abuseipdb]
api_key = "${ABUSEIPDB_API_KEY}"
daily_limit = 1000          # checks per UTC day (free plan: 1000)
CONFIG
        fi
        if [ -n "${SHODAN_API_KEY:-}" ]; then
            cat <<CONFIG

[shodan]
api_key = "${SHODAN_API_KEY}"   # host lookups need a membership or paid plan
CONFIG
        fi
        if [ -n "${GREYNOISE_API_KEY:-}" ]; then
            cat <<CONFIG

[greynoise]
api_key = "${GREYNOISE_API_KEY}"   # free plan: 50 lookups per week
CONFIG
        fi
        if [ "${PEEPHOLE_INTERNETDB:-0}" = 1 ]; then
            cat <<CONFIG

[internetdb]
enabled = true              # Shodan InternetDB: no key, free for non-commercial use only
CONFIG
        fi
        cat <<CONFIG

[scan]
max_workers = 2            # concurrent nmap subprocesses
timeout_secs = 1800        # per-scan wall-clock timeout (adjustable in the admin queue page)
level4_timeout_factor = 4  # level 4 (all ports, -sV -O, scripts) gets this many times timeout_secs, at most 12 h
rescan_cooldown_hours = 24 # per-IP rescan cooldown (one level upgrade allowed)
max_scans_per_hour = 30    # rate cap of this scanner; excess jobs stay queued
# Non-global addresses (loopback, private, link-local, …) are never scanned,
# so list public ranges only: your own servers, monitoring, upstream, e.g.
# never_scan = ["203.0.113.0/24", "2001:db8::/32"]
never_scan = [] # extra CIDRs this node's scanner never scans
CONFIG
        if [ -n "${OWN_ADDRESSES:-}" ]; then
            echo "# Public address that no interface carries (1:1 NAT, found by install.sh):"
            echo "# never scanned, never in the blocklist."
            echo "own_addresses = [$(toml_list "$OWN_ADDRESSES")]"
        fi
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
    info "Wrote ${CONFIG_FILE} (mode 0600 — may contain your MaxMind and API keys)"
    # A reverse-proxy example that fits this node (see nginx_example). A
    # trap with nothing in front (direct, never with the web role) has none.
    NGINX_EXAMPLE="${CONFIG_DIR}/nginx.example.conf"
    if has_role web || { has_role listener && [ "${PEEPHOLE_FRONT:-}" != direct ]; }; then
        nginx_example > "$NGINX_EXAMPLE"
        chmod 0644 "$NGINX_EXAMPLE"
        info "Wrote ${NGINX_EXAMPLE} (reverse-proxy example for this node)"
        rm -f "${CONFIG_DIR}/nginx-stream.example.conf"
        if stream_trap; then
            nginx_stream_example > "${CONFIG_DIR}/nginx-stream.example.conf"
            chmod 0644 "${CONFIG_DIR}/nginx-stream.example.conf"
        fi
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
# The unit is a conffile: an edited unit is kept and the new
# upstream one is placed beside it as peephole.service.new (systemd ignores
# that name). Changes belong in a drop-in (systemctl edit peephole), which the
# installer never touches.
info "Installing systemd service"
UNIT_NEW_WRITTEN=0
unit_sum="$(sha256sum "${src}/deploy/peephole.service" | cut -d' ' -f1)"
if [ ! -e "$UNIT_FILE" ]; then
    install -m 0644 "${src}/deploy/peephole.service" "$UNIT_FILE"
else
    current="$(sha256sum "$UNIT_FILE" | cut -d' ' -f1)"
    recorded="$(cat "$UNIT_MANIFEST" 2>/dev/null || true)"
    if [ "$current" = "$unit_sum" ]; then
        : # identical already
    elif [ "$current" = "$recorded" ] || [[ " ${KNOWN_UNIT_SUMS} " == *" ${current} "* ]]; then
        install -m 0644 "${src}/deploy/peephole.service" "$UNIT_FILE"   # unedited → take upstream
    else
        install -m 0644 "${src}/deploy/peephole.service" "${UNIT_FILE}.new"
        UNIT_NEW_WRITTEN=1
        warn "kept your edited ${UNIT_FILE}; the new upstream unit is ${UNIT_FILE}.new. Merge it, and keep local changes in a drop-in (systemctl edit peephole)."
    fi
fi
printf '%s\n' "$unit_sum" > "$UNIT_MANIFEST"

# Start or restart. With Type=notify the call returns once the listeners are
# bound, and fails if peephole exits first.
start_service() {
    systemctl daemon-reload
    if systemctl is-enabled peephole >/dev/null 2>&1; then
        systemctl restart peephole
    else
        systemctl enable --now peephole
    fi
}

admin_listen="$(sed -n 's/^admin_listen *= *"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -1)"
wait_healthy() {
    [ "${PEEPHOLE_SKIP_HEALTH:-0}" = "1" ] && return 0
    if [ -n "$admin_listen" ]; then
        info "Waiting for http://${admin_listen}/healthz"
        for _ in $(seq 1 20); do
            if curl -fs "http://${admin_listen}/healthz" >/dev/null 2>&1; then return 0; fi
            sleep 1
        done
        # The web role may be switched off in the runtime settings; a notify
        # unit that is active has started all the same.
        if [ "$(systemctl show -p Type --value peephole 2>/dev/null)" = "notify" ] \
                && systemctl is-active --quiet peephole; then
            warn "no answer on http://${admin_listen}/healthz, but the service is up (web role off in the settings?)"
            return 0
        fi
        return 1
    fi
    # No web role, so no HTTP endpoint: the service must be up and stay up.
    # A notify unit is up once started; an older (kept) simple unit only shows
    # a failed start after a moment.
    if [ "$(systemctl show -p Type --value peephole 2>/dev/null)" != "notify" ]; then
        info "Waiting for the service to stay up (no web role, no /healthz)"
        sleep 5
    fi
    systemctl is-active --quiet peephole
}

# Put back what this run changed: binary, unit and, if the new version
# migrated it, the database. The rules of an older version stay in
# ${CONFIG_DIR}/rules (never touched), so it finds them again.
rollback() {
    systemctl stop peephole || true
    mv -f "${INSTALL_BIN}.prev" "$INSTALL_BIN"
    if [ -e "${backup}/peephole.service" ]; then
        cp -p "${backup}/peephole.service" "$UNIT_FILE"
        if [ "$UNIT_NEW_WRITTEN" = 1 ]; then rm -f "${UNIT_FILE}.new"; fi
    fi
    if [ -e "${backup}/unit.sha256" ]; then cp -p "${backup}/unit.sha256" "$UNIT_MANIFEST"; else rm -f "$UNIT_MANIFEST"; fi
    if [ -n "$DB_BACKUP" ] && [ "$(schema_version "$DB_PATH")" != "$DB_SCHEMA" ]; then
        warn "the new version changed the database schema; restoring ${DB_BACKUP} (requests recorded since the backup are lost)"
        rm -f "${DB_PATH}-wal" "${DB_PATH}-shm"
        install -m 0600 "$DB_BACKUP" "$DB_PATH"
    fi
}

started=1
start_service || started=0
if [ "$started" -eq 1 ]; then info "Started peephole ${new_version}"; fi
if [ "$started" -ne 1 ] || ! wait_healthy; then
    journalctl -u peephole -n 30 --no-pager >&2 || true
    if [ "$upgrade" -eq 1 ] && [ -x "${INSTALL_BIN}.prev" ]; then
        warn "the new version did not become healthy; rolling back binary and unit"
        rollback
        if start_service && wait_healthy; then
            die "rolled back to ${installed_version:-the previous version}, which is running again. The log above shows why ${new_version} failed."
        fi
        journalctl -u peephole -n 30 --no-pager >&2 || true
        die "rolled back to ${installed_version:-the previous version}, but the service did not come up either; see journalctl -u peephole.${DB_BACKUP:+ Database backup: ${DB_BACKUP}}"
    fi
    die "peephole did not become healthy; see the log above"
fi

# --- done --------------------------------------------------------------------
if [ "$upgrade" -eq 1 ]; then
    info "Upgraded peephole ${installed_version:-?} → ${new_version}"
    # Once, after an upgrade from a version that read its rules from disk.
    if [ -e "$OLD_RULES_MANIFEST" ]; then
        if [ -d "${CONFIG_DIR}/rules" ]; then
            warn "the signature rules are built into peephole now: ${CONFIG_DIR}/rules is no longer used and was left in place; remove it when you like (edits there have no effect any more)"
        fi
        if grep -q '^rules_dir *=' "$CONFIG_FILE" 2>/dev/null; then
            warn "rules_dir in ${CONFIG_FILE} is ignored; remove that line"
        fi
        rm -f "$OLD_RULES_MANIFEST"
    fi
    exit 0
fi

# --- nginx (first install, when asked) ------------------------------------------
# Runs once peephole is up. Every step that fails puts back what this
# function changed and leaves the manual steps in the summary; the install
# itself has succeeded either way.
NGINX_DONE=0
NGINX_SITE=/etc/nginx/sites-available/peephole
NGINX_LINK=/etc/nginx/sites-enabled/peephole
NGINX_DEFAULT=/etc/nginx/sites-enabled/default
NGINX_STREAM=/etc/nginx/peephole-stream.conf
setup_nginx() {
    local need=() default_target="" out
    if [ -e "$NGINX_LINK" ] || [ -e "$NGINX_SITE" ] || { stream_trap && [ -e "$NGINX_STREAM" ]; }; then
        warn "nginx: ${NGINX_SITE} or ${NGINX_STREAM} already exists; left alone (the steps to do it by hand follow)"
        return 1
    fi
    if stream_trap; then
        # Port 443 goes to the stream config; sites that listen on it
        # themselves have to move behind it first (see the stream example).
        local others
        others="$(grep -lsE '^[[:space:]]*listen[[:space:]]+([^;#[:space:]]*[]:])?443([[:space:];]|$)' /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf || true)"
        if [ -n "$others" ]; then
            warn "nginx: port 443 is already used by $(printf '%s' "$others" | tr '\n' ' ')- move those sites behind the stream config first (see ${CONFIG_DIR}/nginx-stream.example.conf); left alone"
            return 1
        fi
    fi
    command -v nginx >/dev/null 2>&1 || need+=(nginx)
    # The stream module, where the distribution packages it on its own.
    if stream_trap && ! dpkg -s libnginx-mod-stream >/dev/null 2>&1 \
            && apt-cache show libnginx-mod-stream >/dev/null 2>&1; then
        need+=(libnginx-mod-stream)
    fi
    if has_role web && ! command -v certbot >/dev/null 2>&1; then need+=(certbot python3-certbot-nginx); fi
    if [ "${#need[@]}" -gt 0 ]; then
        if [ "${PEEPHOLE_SKIP_APT:-0}" = 1 ]; then
            warn "nginx: ${need[*]} not installed and PEEPHOLE_SKIP_APT=1; skipped"
            return 1
        fi
        info "Installing ${need[*]}"
        export DEBIAN_FRONTEND=noninteractive
        if ! { apt-get update -qq && apt-get install -y -qq "${need[@]}"; }; then
            warn "nginx: installing ${need[*]} failed"
            return 1
        fi
    fi
    systemctl enable --now nginx || { warn "nginx: the service does not start"; return 1; }
    if has_role web && [ ! -e "/etc/letsencrypt/live/${PEEPHOLE_DOMAIN}/fullchain.pem" ]; then
        info "Requesting a Let's Encrypt certificate for ${PEEPHOLE_DOMAIN}"
        local contact=(--register-unsafely-without-email)
        [ -n "${PEEPHOLE_ACME_EMAIL:-}" ] && contact=(-m "$PEEPHOLE_ACME_EMAIL")
        # While the distribution's default site still serves port 80.
        if ! certbot certonly --nginx -d "$PEEPHOLE_DOMAIN" --non-interactive --agree-tos \
                "${contact[@]}" --deploy-hook "systemctl reload nginx"; then
            warn "nginx: no certificate for ${PEEPHOLE_DOMAIN} (does its DNS point here, is port 80 reachable?)"
            return 1
        fi
    fi
    if has_role listener && [ -e "$NGINX_DEFAULT" ]; then
        # The catch-all needs default_server on port 80, which the stock
        # default site claims. Only a link is taken out (and put back on
        # failure); a site written in place is someone's configuration.
        if [ ! -L "$NGINX_DEFAULT" ]; then
            warn "nginx: ${NGINX_DEFAULT} is not a link to a stock site; left alone"
            return 1
        fi
        default_target="$(readlink "$NGINX_DEFAULT")"
        rm -f "$NGINX_DEFAULT"
    fi
    install -m 0644 "${CONFIG_DIR}/nginx.example.conf" "$NGINX_SITE"
    if [ ! -e /proc/net/if_inet6 ]; then
        # nginx refuses to start on [::] listeners without IPv6.
        sed -i '/^ *listen \[::\]/d' "$NGINX_SITE"
        info "nginx: no IPv6 on this machine; the site listens on IPv4 only"
    fi
    ln -s ../sites-available/peephole "$NGINX_LINK"
    local stream_added=0
    if stream_trap; then
        install -m 0644 "${CONFIG_DIR}/nginx-stream.example.conf" "$NGINX_STREAM"
        [ -e /proc/net/if_inet6 ] || sed -i '/^ *listen \[::\]/d' "$NGINX_STREAM"
        if ! grep -qF "include ${NGINX_STREAM};" /etc/nginx/nginx.conf; then
            printf '# peephole: port 443 by server name (see %s)\ninclude %s;\n' \
                "$NGINX_STREAM" "$NGINX_STREAM" >> /etc/nginx/nginx.conf
            stream_added=1
        fi
    fi
    undo_nginx() {
        rm -f "$NGINX_LINK" "$NGINX_SITE" "$NGINX_STREAM"
        if [ "$stream_added" = 1 ]; then
            sed -i "\|^# peephole: port 443 by server name|d; \|^include ${NGINX_STREAM};|d" /etc/nginx/nginx.conf
        fi
        if [ -n "$default_target" ]; then ln -s "$default_target" "$NGINX_DEFAULT"; fi
    }
    if ! out="$(nginx -t 2>&1)"; then
        printf '%s\n' "$out" >&2
        undo_nginx
        warn "nginx: the configuration test failed; nginx was left as it was"
        return 1
    fi
    if ! systemctl reload nginx; then
        undo_nginx
        systemctl reload nginx || true
        warn "nginx: reload failed; the changes were taken back"
        return 1
    fi
    info "nginx: site ${NGINX_SITE} enabled${default_target:+ (the default site was disabled)}"
    return 0
}
if [ "${PEEPHOLE_NGINX:-0}" = 1 ] && [ -e "${CONFIG_DIR}/nginx.example.conf" ]; then
    if setup_nginx; then NGINX_DONE=1; fi
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
if [ "$NGINX_DONE" = 1 ]; then
    echo "  - nginx is configured: ${NGINX_SITE} (generated from ${CONFIG_DIR}/nginx.example.conf)."
    if [ -n "$admin_listen" ]; then
        echo "    The certificate for ${PEEPHOLE_DOMAIN} renews automatically (certbot's systemd timer)."
    fi
elif [ -e "${CONFIG_DIR}/nginx.example.conf" ] && { [ -n "$admin_listen" ] || [ "${PEEPHOLE_FRONT:-}" != remote ]; }; then
    # A trap-only node behind a remote proxy needs no nginx here (below).
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
    if [ -e "${CONFIG_DIR}/nginx-stream.example.conf" ]; then
        echo "      apt-get install libnginx-mod-stream   (where nginx's stream module is separate)"
        echo "      cp ${CONFIG_DIR}/nginx-stream.example.conf ${NGINX_STREAM}"
        echo "      echo 'include ${NGINX_STREAM};' >> /etc/nginx/nginx.conf"
        echo "        (port 443 by server name: TLS for unknown names goes to the trap untouched)"
    fi
    echo "      nginx -t && systemctl reload nginx"
    if [ -n "$admin_listen" ] && [ ! -e "${CONFIG_DIR}/nginx-stream.example.conf" ]; then
        echo "    (the example refuses TLS for unknown names with ssl_reject_handshake: nginx >= 1.19.4)"
    fi
fi
case "${PEEPHOLE_FRONT:-}" in
    direct)
        # The ports to open: the trap's, and the cluster's when peers dial it.
        open_ports=(80 443)
        if grep -q '^advertise' "$CONFIG_FILE"; then open_ports+=("${PEEPHOLE_CLUSTER_LISTEN##*:}"); fi
        echo "  - The trap listens on ports 80 and 443 itself (nothing in front of it). Open $(printf '%s/tcp ' "${open_ports[@]}" | sed 's/ $//; s/ /, /g')"
        echo "    in any firewall in front of this machine (cloud security group, provider firewall)."
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
            echo "    ufw is active here; the installer did not change it. To open them:"
            echo "      ufw allow 80/tcp"
            echo "      ufw allow 443/tcp"
            if [ "${#open_ports[@]}" -gt 2 ]; then
                echo "      ufw allow from <other node> to any port ${open_ports[2]} proto tcp   (per node; or ufw allow ${open_ports[2]}/tcp)"
            fi
        fi
        ;;
    remote)
        echo "  - Your proxy (trusted_proxies = ${PEEPHOLE_TRUSTED_PROXIES}) must:"
        echo "      send plain HTTP that matches no real site to ${trap_listen}, with X-Forwarded-For set to the"
        echo "        client's address (not appended to what the client sent);"
        echo "      pass TLS for unknown names untouched (TCP), with a PROXY protocol v2 header, to ${TRAP_TLS_LISTEN};"
        echo "      not health-check that TLS backend: a PROXY header without a client (LOCAL) is refused."
        echo "    trusted_proxies must name that proxy only: whoever is in it is believed about the client address."
        if [ -z "$admin_listen" ] && [ -e "${CONFIG_DIR}/nginx.example.conf" ]; then
            echo "    For an nginx proxy, ${CONFIG_DIR}/nginx.example.conf shows how (point it at this machine)."
        fi
        ;;
    local)
        if [ "$NGINX_DONE" != 1 ]; then
            echo "  - Send requests that match no real site to the trap listener (${trap_listen}); see the nginx example."
        fi
        ;;
esac
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
    if [ "$NGINX_DONE" != 1 ]; then
        echo "  - Terminate TLS with nginx in front of the admin listener (${admin_listen}) using the example config."
    fi
    echo "  - Enroll your first FIDO2 admin key at https://${PEEPHOLE_DOMAIN:-<your-domain>}/enroll"
    if [ -n "$token" ]; then
        printf '    one-time setup token: %s\n' "$token"
    else
        printf '    the one-time setup token is in the service log: journalctl -u peephole | grep -A2 token\n'
        printf '    (or issue a new one: peephole admin reset-token)\n'
    fi
fi
}

[ "${PEEPHOLE_NO_MAIN:-0}" = 1 ] || main "$@"
