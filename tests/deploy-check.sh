#!/usr/bin/env bash
# Checks the files in deploy/ without installing anything:
# - deploy/nginx.example.conf and deploy/nginx-stream.example.conf are exactly
#   what install.sh generates for a full node behind a local nginx (one source
#   of truth: install.sh);
# - nginx accepts the example for every role combination (when nginx is
#   installed; the certificates are swapped for a throwaway self-signed one);
# - systemd-analyze accepts the unit (when available).
# Installs nothing. nginx -t opens the listen sockets (80, 443), so run it as
# root (CI: sudo). Usage: tests/deploy-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

gen() { # gen <roles> <local proxy 1|0> [--nginx-stream-example]
    env -u PEEPHOLE_DOMAIN -u PEEPHOLE_TRUSTED_PROXIES \
        PEEPHOLE_ROLES="$1" PEEPHOLE_LOCAL_PROXY="$2" bash install.sh "${3:---nginx-example}"
}

echo "== deploy/nginx.example.conf matches install.sh --nginx-example"
if ! gen listener,scanner,web 1 | diff -u deploy/nginx.example.conf -; then
    echo "deploy/nginx.example.conf is out of date; regenerate it with:"
    echo "  bash install.sh --nginx-example > deploy/nginx.example.conf"
    exit 1
fi
echo "== deploy/nginx-stream.example.conf matches install.sh --nginx-stream-example"
if ! gen listener,scanner,web 1 --nginx-stream-example | diff -u deploy/nginx-stream.example.conf -; then
    echo "deploy/nginx-stream.example.conf is out of date; regenerate it with:"
    echo "  bash install.sh --nginx-stream-example > deploy/nginx-stream.example.conf"
    exit 1
fi
echo "== the examples never name another proxy product"
if grep -qi 'ha''proxy' deploy/*.conf deploy/*.toml; then
    echo "deploy/ names another proxy product"
    exit 1
fi

echo "== install.sh helpers: port check, addresses, cloud detection"
(
    # Only the helpers above main; nothing is installed.
    PEEPHOLE_NO_MAIN=1
    # shellcheck source=install.sh
    . ./install.sh
    fail() { echo "install.sh helper check failed: $*"; exit 1; }
    # Listening: 0.0.0.0:80, 127.0.0.1:8080, [::]:443, ::ffff:127.0.0.1:7443;
    # 127.0.0.1:8081 is only a connection (state 01), not a listener.
    mkdir -p "$work/net"
    cat > "$work/net/tcp" <<'TCP'
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0 100 0 0 10 0
   2: 0100007F:1F91 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0 100 0 0 10 0
TCP
    cat > "$work/net/tcp6" <<'TCP'
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1 0 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1D13 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5 1 0 100 0 0 10 0
TCP
    export PEEPHOLE_PROC_NET="$work/net"
    for taken in "0.0.0.0 80" "127.0.0.1 80" "0.0.0.0 8080" "127.0.0.1 8080" "[::] 8080" \
            "127.0.0.1 443" "0.0.0.0 443" "127.0.0.1 7443" "0.0.0.0 7443"; do
        # shellcheck disable=SC2086  # host and port as two arguments
        port_in_use $taken || fail "port_in_use $taken: expected in use"
    done
    for free in "127.0.0.2 8080" "127.0.0.1 8081" "0.0.0.0 8081" "10.0.0.1 7443" "0.0.0.0 9999"; do
        # shellcheck disable=SC2086
        if port_in_use $free; then fail "port_in_use $free: expected free"; fi
    done
    # Without IPv6 there is no tcp6.
    rm "$work/net/tcp6"
    port_in_use 0.0.0.0 80 || fail "port_in_use without tcp6"
    if port_in_use 127.0.0.1 443; then fail "port_in_use: 443 is only in the removed tcp6"; fi
    # The interface addresses without ip(8): from fib_trie.
    cat > "$work/net/fib_trie" <<'FIB'
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 127.0.0.1
        /32 host LOCAL
     |-- 192.0.2.2
        /32 host LOCAL
     |-- 192.0.2.255
        /32 link BROADCAST
Local:
     |-- 192.0.2.2
        /32 host LOCAL
FIB
    mkdir -p "$work/bin"
    for t in awk sort sed tr; do ln -sf "$(command -v "$t")" "$work/bin/$t"; done
    [ "$(PATH="$work/bin" local_addresses | paste -sd' ' -)" = "127.0.0.1 192.0.2.2" ] \
        || fail "local_addresses from fib_trie: $(PATH="$work/bin" local_addresses | paste -sd' ' -)"
    unset PEEPHOLE_PROC_NET
    for ip in 192.0.2.1 255.255.255.255 2001:db8::1 ::ffff:192.0.2.1; do valid_ip "$ip" || fail "valid_ip $ip"; done
    for ip in 256.1.1.1 1.2.3 example.net "" 1.2.3.4/32; do
        if valid_ip "$ip"; then fail "valid_ip accepted '$ip'"; fi
    done
    for ip in 203.0.113.5 100.128.0.1 172.32.0.1; do public_ipv4 "$ip" || fail "public_ipv4 $ip"; done
    for ip in 10.1.2.3 172.16.0.1 172.31.255.255 192.168.1.1 127.0.0.1 169.254.169.254 100.64.0.1 100.127.0.1; do
        if public_ipv4 "$ip"; then fail "public_ipv4 accepted $ip"; fi
    done
    [ "$(toml_list ' 192.0.2.5, 2001:db8::5 ,')" = '"192.0.2.5","2001:db8::5"' ] || fail "toml_list"
    # DMI: Azure needs its asset tag (Hyper-V elsewhere says the same otherwise).
    dmi() { # dmi <vendor> <product> <bios vendor> <asset tag>
        rm -rf "$work/dmi"; mkdir -p "$work/dmi"
        printf '%s\n' "$1" > "$work/dmi/sys_vendor"; printf '%s\n' "$2" > "$work/dmi/product_name"
        printf '%s\n' "$3" > "$work/dmi/bios_vendor"; printf '%s\n' "$4" > "$work/dmi/chassis_asset_tag"
        cloud_from_dmi "$work/dmi"
    }
    [ "$(dmi "Amazon EC2" "m5.large" "Amazon EC2" "Amazon EC2")" = "Amazon Web Services" ] || fail "dmi: EC2"
    [ "$(dmi Xen "HVM domU" Amazon "")" = "Amazon Web Services" ] || fail "dmi: EC2 on Xen"
    [ "$(dmi Google "Google Compute Engine" Google "")" = "Google Cloud" ] || fail "dmi: GCE"
    [ "$(dmi "Microsoft Corporation" "Virtual Machine" "Microsoft Corporation" 7783-7084-3265-9085-8269-3286-77)" = "Microsoft Azure" ] || fail "dmi: Azure"
    [ -z "$(dmi "Microsoft Corporation" "Virtual Machine" "Microsoft Corporation" "None")" ] || fail "dmi: Hyper-V is not Azure"
    [ "$(dmi "Alibaba Cloud" "Alibaba Cloud ECS" SeaBIOS "")" = "Alibaba Cloud" ] || fail "dmi: Alibaba"
    [ "$(dmi QEMU "Standard PC" SeaBIOS OracleCloud.com)" = "Oracle Cloud" ] || fail "dmi: Oracle"
    [ -z "$(dmi QEMU "Standard PC (Q35 + ICH9, 2009)" SeaBIOS "")" ] || fail "dmi: plain QEMU"
    [ -z "$(cloud_from_dmi "$work/nonexistent")" ] || fail "dmi: no DMI data"
)

if command -v nginx >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
    echo "== nginx -t on every role combination ($(nginx -v 2>&1))"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
        -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
    # nginx -t opens the listen sockets; some containers have no IPv6.
    no_v6=()
    if [ ! -e /proc/net/if_inet6 ]; then
        echo "   (no IPv6 here: the [::] listen lines are left out of the test)"
        no_v6=(-e '/listen \[::\]/d')
    fi
    for combo in "listener,scanner,web 1" "listener,web 0" "web 1" "listener 1" "listener,scanner 0"; do
        read -r roles local_proxy <<<"$combo"
        gen "$roles" "$local_proxy" \
            | sed -e "s|/etc/letsencrypt/live/[^ ;]*/fullchain.pem|$work/cert.pem|" \
                  -e "s|/etc/letsencrypt/live/[^ ;]*/privkey.pem|$work/key.pem|" \
                  "${no_v6[@]}" > "$work/site.conf"
        gen "$roles" "$local_proxy" --nginx-stream-example | sed "${no_v6[@]:-}" > "$work/stream.conf"
        # The stream module is dynamic on Debian/Ubuntu (libnginx-mod-stream);
        # by absolute path, as module paths resolve against the -p prefix.
        modules=""
        so=/usr/lib/nginx/modules/ngx_stream_module.so
        [ -e "$so" ] && modules="load_module $so;"
        cat > "$work/nginx.conf" <<CONF
$modules
include $work/stream.conf;
pid $work/nginx.pid;
error_log $work/error.log;
events {}
http {
    access_log off;
    client_body_temp_path $work/body;
    proxy_temp_path $work/proxy;
    fastcgi_temp_path $work/fastcgi;
    uwsgi_temp_path $work/uwsgi;
    scgi_temp_path $work/scgi;
    include $work/site.conf;
}
CONF
        if ! nginx -t -q -p "$work" -c "$work/nginx.conf"; then
            echo "nginx rejects the example for roles '$roles' (local proxy $local_proxy):"
            cat "$work/site.conf"
            exit 1
        fi
    done
else
    echo "== nginx or openssl not installed: nginx -t skipped"
fi

if command -v systemd-analyze >/dev/null 2>&1; then
    echo "== systemd-analyze verify deploy/peephole.service"
    # verify insists that ExecStart exists; point it at a binary that does.
    sed 's|^ExecStart=/usr/local/bin/peephole|ExecStart=/bin/true|' deploy/peephole.service \
        > "$work/peephole.service"
    systemd-analyze verify "$work/peephole.service"
else
    echo "== systemd-analyze not available: unit check skipped"
fi
echo "== ok"
