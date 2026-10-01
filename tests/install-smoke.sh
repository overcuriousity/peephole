#!/usr/bin/env bash
# Exercises install.sh against a locally served tarball: fresh install,
# no-op re-run, forced upgrade preserving an edited rule file.
set -euo pipefail
cd "$(dirname "$0")/.."
ASSET="peephole-x86_64-unknown-linux-gnu"
apt-get update -qq && apt-get install -y -qq curl ca-certificates python3 systemd nmap sqlite3 procps >/dev/null

# Build a tarball from the release binary exactly like release.yml does.
rm -rf "/tmp/$ASSET" /tmp/srv && mkdir -p "/tmp/$ASSET/deploy" /tmp/srv
# PEEPHOLE_BIN lets a developer point at a musl build when the host glibc is newer than the image.
cp "${PEEPHOLE_BIN:-target/release/peephole}" "/tmp/$ASSET/"
cp -r rules "/tmp/$ASSET/rules"
cp deploy/peephole.service deploy/config.example.toml deploy/nginx.example.conf "/tmp/$ASSET/deploy/"
printf 'test1 2026-01-01T00:00:00Z\n' > "/tmp/$ASSET/VERSION"
( cd /tmp && tar -czf "srv/$ASSET.tar.gz" "$ASSET" && cd srv && sha256sum "$ASSET.tar.gz" > "$ASSET.tar.gz.sha256" )
( cd /tmp/srv && python3 -m http.server 8999 >/dev/null 2>&1 & )
sleep 1

# systemd is not PID 1 in a container: stub systemctl so the script's
# service steps become no-ops we can observe.
mkdir -p /tmp/bin
cat > /tmp/bin/systemctl <<'STUB'
#!/bin/sh
echo "systemctl $*" >> /tmp/systemctl.log
case "$1" in
  is-enabled) [ -e /tmp/enabled ]; exit $? ;;
  enable) touch /tmp/enabled ;;
esac
exit 0
STUB
chmod +x /tmp/bin/systemctl
export PATH="/tmp/bin:$PATH"
export PEEPHOLE_SKIP_APT=1 PEEPHOLE_SKIP_HEALTH=1 BASE_URL="http://127.0.0.1:8999"
export MAXMIND_ACCOUNT_ID=1 MAXMIND_LICENSE_KEY=k PEEPHOLE_DOMAIN=peephole.test PEEPHOLE_TRUSTED_PROXIES=10.0.0.0/8

echo "== token extraction survives journalctl prefixes"
tok="$(printf 'Sep 30 10:00:00 host peephole[123]: Open /enroll on the admin interface and enter this one-time token:\nSep 30 10:00:00 host peephole[123]: \nSep 30 10:00:00 host peephole[123]:   3f2a1c4e-1111-4222-8333-444455556666\n' | bash install.sh --extract-token)"
[ "$tok" = "3f2a1c4e-1111-4222-8333-444455556666" ] || { echo "token extraction broken: '$tok'"; exit 1; }

echo "== refuses to install when systemd is not PID 1 (unless overridden)"
if PEEPHOLE_ALLOW_NO_SYSTEMD='' bash install.sh >/tmp/nopid1.log 2>&1; then echo "expected failure"; exit 1; fi
grep -q "PID 1" /tmp/nopid1.log
export PEEPHOLE_ALLOW_NO_SYSTEMD=1

echo "== fresh install"
bash install.sh
test -x /usr/local/bin/peephole
test -f /etc/peephole/config.toml
test -f /etc/peephole/rules/sqli.toml
test -f /etc/peephole/nginx.example.conf
test -f /var/lib/peephole/.installed-rules.sha256
grep -q 'peephole.test' /etc/peephole/config.toml
grep -q 'server_name peephole.test;' /etc/peephole/nginx.example.conf
grep -q 'default_server' /etc/peephole/nginx.example.conf
grep -q 'systemctl enable --now peephole' /tmp/systemctl.log

echo "== re-run is a no-op"
out="$(bash install.sh)"
echo "$out" | grep -q "already up to date"

echo "== forced upgrade keeps an edited rule and drops .new beside it"
echo '# operator edit' >> /etc/peephole/rules/sqli.toml
printf 'test2 2026-01-02T00:00:00Z\n' > "/tmp/$ASSET/VERSION"
echo '# upstream change' >> "/tmp/$ASSET/rules/xss.toml"
echo '# upstream change' >> "/tmp/$ASSET/rules/sqli.toml"
( cd /tmp && tar -czf "srv/$ASSET.tar.gz" "$ASSET" && cd srv && sha256sum "$ASSET.tar.gz" > "$ASSET.tar.gz.sha256" )
echo '# operator note' >> /etc/peephole/nginx.example.conf
PEEPHOLE_FORCE=1 bash install.sh
grep -q '# operator note' /etc/peephole/nginx.example.conf
grep -q '# operator edit' /etc/peephole/rules/sqli.toml
test -f /etc/peephole/rules/sqli.toml.new
grep -q '# upstream change' /etc/peephole/rules/xss.toml
test ! -e /etc/peephole/rules/xss.toml.new
grep -q 'systemctl restart peephole' /tmp/systemctl.log
test -x /usr/local/bin/peephole.prev

echo "== fresh headless scanner in distributed mode: no domain, no MaxMind"
rm -rf /etc/peephole /var/lib/peephole /usr/local/bin/peephole /usr/local/bin/peephole.prev /tmp/enabled
env -u MAXMIND_ACCOUNT_ID -u MAXMIND_LICENSE_KEY -u PEEPHOLE_DOMAIN \
    PEEPHOLE_ROLES=scanner PEEPHOLE_CLUSTER_NAME=scanner-1 PEEPHOLE_CLUSTER_LISTEN=0.0.0.0:7443 \
    bash install.sh > /tmp/headless.log 2>&1 || { cat /tmp/headless.log; exit 1; }
grep -q '^\[cluster\]' /etc/peephole/config.toml
grep -q '^listener = false' /etc/peephole/config.toml
grep -q '^web = false' /etc/peephole/config.toml
if grep -q 'webauthn\|maxmind\|trap_listen\|admin_listen' /etc/peephole/config.toml; then
    echo "headless config has role-specific settings"; exit 1
fi
grep -q 'ed25519:' /tmp/headless.log
test ! -e /etc/peephole/nginx.example.conf
/usr/local/bin/peephole check-config /etc/peephole/config.toml
# The node lists itself once the daemon has run (`cluster members` is read-only
# and systemd is stubbed here); the config names it.
grep -q '^node_name = "scanner-1"' /etc/peephole/config.toml
reset_install() {
    rm -rf /etc/peephole /var/lib/peephole /usr/local/bin/peephole /usr/local/bin/peephole.prev /tmp/enabled
}

echo "== wizard: trap only, behind a local nginx (answers typed at the prompts)"
reset_install
# trap? yes · scanner? no · web? no · local proxy? yes · cluster? no · MaxMind: skip
printf 'y\nn\nn\ny\n\n\n' > /tmp/answers
# PEEPHOLE_TRUSTED_PROXIES stays preset (10.0.0.0/8): the local proxy answer replaces it, with a warning.
env -u MAXMIND_ACCOUNT_ID -u MAXMIND_LICENSE_KEY -u PEEPHOLE_DOMAIN \
    PEEPHOLE_TTY=/tmp/answers bash install.sh > /tmp/wizard1.log 2>&1 || { cat /tmp/wizard1.log; exit 1; }
grep -q 'PEEPHOLE_TRUSTED_PROXIES.*ignored' /tmp/wizard1.log
grep -q '^listener = true' /etc/peephole/config.toml
grep -q '^scanner = false' /etc/peephole/config.toml
grep -q '^web = false' /etc/peephole/config.toml
grep -q '^trap_listen = "127.0.0.1:8080"' /etc/peephole/config.toml
grep -q '^trusted_proxies = \["127.0.0.1/32","::1/128"\]' /etc/peephole/config.toml
if grep -q 'webauthn\|maxmind\|\[cluster\]\|admin_listen' /etc/peephole/config.toml; then
    echo "trap-only config has other roles' settings"; cat /etc/peephole/config.toml; exit 1
fi
/usr/local/bin/peephole check-config /etc/peephole/config.toml
grep -q 'trap listener (127.0.0.1:8080)' /tmp/wizard1.log
grep -q 'default_server' /etc/peephole/nginx.example.conf
grep -q 'proxy_pass http://127.0.0.1:8080' /etc/peephole/nginx.example.conf
# shellcheck disable=SC2016  # the dollar sign is literal nginx syntax
grep -qF 'X-Forwarded-For $remote_addr' /etc/peephole/nginx.example.conf
if grep -q 'server_name peephole\|8443\|proxy_add_x_forwarded_for' /etc/peephole/nginx.example.conf; then
    echo "trap-only nginx example has an admin block or a spoofable header"; exit 1
fi

echo "== wizard: no role at all is refused before anything is written"
reset_install
printf 'n\nn\nn\n' > /tmp/answers
if env -u MAXMIND_ACCOUNT_ID -u MAXMIND_LICENSE_KEY -u PEEPHOLE_DOMAIN \
    PEEPHOLE_TTY=/tmp/answers bash install.sh > /tmp/wizard2.log 2>&1; then
    echo "expected failure"; exit 1
fi
grep -q "at least one" /tmp/wizard2.log
test ! -e /etc/peephole/config.toml
test ! -e /usr/local/bin/peephole

echo "== wizard: a quote in an answer is refused"
reset_install
# trap? no · scanner? no · web? yes · domain with a quote
printf 'n\nn\ny\nbad"domain\n' > /tmp/answers
if env -u MAXMIND_ACCOUNT_ID -u MAXMIND_LICENSE_KEY -u PEEPHOLE_DOMAIN \
    PEEPHOLE_TTY=/tmp/answers bash install.sh > /tmp/wizard3.log 2>&1; then
    echo "expected failure"; exit 1
fi
grep -q "not allowed" /tmp/wizard3.log
test ! -e /etc/peephole/config.toml
test ! -e /usr/local/bin/peephole
echo "== wizard: scanner in a cluster with remote configuration on"
reset_install
# trap? no · scanner? yes · web? no · cluster? yes · name · listen (default) ·
# advertise · token (none) · remote config? yes · MaxMind: skip
printf 'n\ny\nn\ny\nscanner-9\n\nscan9.example:7443\n\ny\n\n' > /tmp/answers
env -u MAXMIND_ACCOUNT_ID -u MAXMIND_LICENSE_KEY -u PEEPHOLE_DOMAIN \
    PEEPHOLE_TTY=/tmp/answers bash install.sh > /tmp/wizard4.log 2>&1 || { cat /tmp/wizard4.log; exit 1; }
grep -q '^node_name = "scanner-9"' /etc/peephole/config.toml
grep -q '^listen = "0.0.0.0:7443"' /etc/peephole/config.toml
grep -q '^advertise = "scan9.example:7443"' /etc/peephole/config.toml
grep -q '^remote_config = true' /etc/peephole/config.toml
grep -q 'peephole-cfg1:' /tmp/wizard4.log
grep -q 'ed25519:' /tmp/wizard4.log
/usr/local/bin/peephole check-config /etc/peephole/config.toml | grep -q 'remote config: on'

echo "== unattended: a bad join token does not fail the install"
reset_install
env -u MAXMIND_ACCOUNT_ID -u MAXMIND_LICENSE_KEY -u PEEPHOLE_DOMAIN \
    PEEPHOLE_ROLES=scanner PEEPHOLE_CLUSTER_NAME=scanner-2 PEEPHOLE_CLUSTER_LISTEN=0.0.0.0:7443 \
    PEEPHOLE_JOIN_TOKEN=peephole1:garbage PEEPHOLE_REMOTE_CONFIG=0 \
    bash install.sh > /tmp/badjoin.log 2>&1 || { cat /tmp/badjoin.log; exit 1; }
grep -q 'joining the cluster failed' /tmp/badjoin.log
grep -q '^remote_config = false' /etc/peephole/config.toml
if grep -q 'peephole-cfg1:' /tmp/badjoin.log; then echo "locked node printed a config key"; exit 1; fi
echo "== ok"
