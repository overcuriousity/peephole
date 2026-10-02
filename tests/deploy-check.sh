#!/usr/bin/env bash
# Checks the files in deploy/ without installing anything:
# - deploy/nginx.example.conf is exactly what install.sh generates for a full
#   node behind a local nginx (one source of truth: install.sh);
# - nginx accepts the example for every role combination (when nginx is
#   installed; the certificates are swapped for a throwaway self-signed one);
# - systemd-analyze accepts the unit (when available).
# Needs no root. Usage: tests/deploy-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

gen() { # gen <roles> <local proxy 1|0>
    env -u PEEPHOLE_DOMAIN -u PEEPHOLE_TRUSTED_PROXIES \
        PEEPHOLE_ROLES="$1" PEEPHOLE_LOCAL_PROXY="$2" bash install.sh --nginx-example
}

echo "== deploy/nginx.example.conf matches install.sh --nginx-example"
if ! gen listener,scanner,web 1 | diff -u deploy/nginx.example.conf -; then
    echo "deploy/nginx.example.conf is out of date; regenerate it with:"
    echo "  bash install.sh --nginx-example > deploy/nginx.example.conf"
    exit 1
fi

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
        cat > "$work/nginx.conf" <<CONF
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
