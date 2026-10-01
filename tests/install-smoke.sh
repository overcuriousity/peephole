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
PEEPHOLE_FORCE=1 bash install.sh
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
/usr/local/bin/peephole check-config /etc/peephole/config.toml
/usr/local/bin/peephole cluster members /etc/peephole/config.toml | grep -q 'scanner-1'
echo "== ok"
