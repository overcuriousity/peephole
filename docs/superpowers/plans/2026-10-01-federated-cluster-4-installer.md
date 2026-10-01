# Federated Cluster, Part 4: Installer Wizard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A first install asks the deployer every decision the federated cluster gives them (trap, scanner, web interface, cluster, remote configuration, MaxMind) and leaves a working config plus a ready nginx example for the admin site and the catch-all trap.

**Architecture:** `install.sh` stays one bash function. Every decision is a variable: preset in the environment (unattended installs, unchanged), otherwise asked on the terminal. The questions read from one file descriptor, so a test can feed answers from a file. The nginx example is generated from the answers on first install; upgrades never touch config or example.

**Tech Stack:** bash, shellcheck, the container smoke test `tests/install-smoke.sh`.

**Spec:** `docs/superpowers/specs/2026-10-01-federated-cluster-design.md`, section 7.

## Global Constraints

- The wizard runs on first install only. A re-run updates the binary and leaves config and nginx example untouched.
- Every answer can be preset by an environment variable, which skips its prompt. With no terminal and no preset, behaviour is exactly as before this plan (all roles on, no cluster, required values missing → error).
- Wording: the listener role is called "trap" in every prompt and message; the config keys stay `listener`, `scanner`, `web`.
- The installer never installs or modifies nginx. It writes `/etc/peephole/nginx.example.conf` and prints the steps.
- The catch-all block passes the client address as `X-Forwarded-For $remote_addr` (never `$proxy_add_x_forwarded_for`), so a client-supplied header cannot spoof it.
- `shellcheck install.sh tests/install-smoke.sh` stays clean.

## Review Focus

1. A value typed at a prompt contains a quote, backslash or newline. Expected: refused before anything is written to the config.
2. All three role questions answered "no". Expected: a clear error, nothing installed half-way into a config.
3. The join token is wrong or the inviter is unreachable. Expected: the install completes, says the join failed and how to retry.
4. Web interface off. Expected: no domain question, no admin block in the nginx example, no `/healthz` wait.
5. A re-run on an existing install with wizard variables set. Expected: they are ignored; config and nginx example unchanged.

## File Structure

| File | Change |
|---|---|
| `install.sh` | wizard, local-proxy handling, remote config, generated nginx example, closing summary |
| `deploy/nginx.example.conf` | generic reference with the catch-all trap blocks |
| `tests/install-smoke.sh` | wizard runs fed from an answers file; role-specific nginx example; remote config |
| `README.md` | Install section |

### Variables

| Variable | Meaning | Asked when |
|---|---|---|
| `PEEPHOLE_ROLES` | comma list of `listener,scanner,web` | not set and a terminal is there: three yes/no questions |
| `PEEPHOLE_LOCAL_PROXY` | `1`: nginx on this machine fronts the trap | trap role on |
| `PEEPHOLE_TRUSTED_PROXIES` | CIDRs whose `X-Forwarded-For` is trusted | trap on and no local proxy |
| `PEEPHOLE_DOMAIN` | admin site domain | web role on |
| `PEEPHOLE_CLUSTER` | `1`/`0`: take part in a cluster (implied `1` when `PEEPHOLE_CLUSTER_NAME` is set) | always (terminal) |
| `PEEPHOLE_CLUSTER_NAME`, `_LISTEN`, `_ADVERTISE` | as before | cluster on |
| `PEEPHOLE_JOIN_TOKEN` | invite to join with | cluster on (empty: start a new cluster or join later) |
| `PEEPHOLE_REMOTE_CONFIG` | `1`: config key holders may change this node's settings | cluster on |
| `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` | as before | always (optional) |
| `PEEPHOLE_TTY` | file to read answers from instead of `/dev/tty` (tests) | — |

---

### Task 1: Questions that can be fed from a file, and the role questions

**Files:**
- Modify: `install.sh`, `tests/install-smoke.sh`

- [ ] **Step 1: Write the failing smoke test.** Append to `tests/install-smoke.sh`, before the final `echo "== ok"`:

```bash
reset_install() {
    rm -rf /etc/peephole /var/lib/peephole /usr/local/bin/peephole /usr/local/bin/peephole.prev /tmp/enabled
}

echo "== wizard: trap only, behind a local nginx (answers typed at the prompts)"
reset_install
# trap? yes · scanner? no · web? no · local proxy? yes · cluster? no · MaxMind: skip
printf 'y\nn\nn\ny\nn\n\n' > /tmp/answers
env -u MAXMIND_ACCOUNT_ID -u MAXMIND_LICENSE_KEY -u PEEPHOLE_DOMAIN -u PEEPHOLE_TRUSTED_PROXIES \
    PEEPHOLE_TTY=/tmp/answers bash install.sh > /tmp/wizard1.log 2>&1 || { cat /tmp/wizard1.log; exit 1; }
grep -q '^listener = true' /etc/peephole/config.toml
grep -q '^scanner = false' /etc/peephole/config.toml
grep -q '^web = false' /etc/peephole/config.toml
grep -q '^trap_listen = "127.0.0.1:8080"' /etc/peephole/config.toml
grep -q '^trusted_proxies = \["127.0.0.1/32","::1/128"\]' /etc/peephole/config.toml
if grep -q 'webauthn\|maxmind\|\[cluster\]\|admin_listen' /etc/peephole/config.toml; then
    echo "trap-only config has other roles' settings"; cat /etc/peephole/config.toml; exit 1
fi
/usr/local/bin/peephole check-config /etc/peephole/config.toml

echo "== wizard: no role at all is refused before anything is written"
reset_install
printf 'n\nn\nn\n' > /tmp/answers
if env -u MAXMIND_ACCOUNT_ID -u MAXMIND_LICENSE_KEY -u PEEPHOLE_DOMAIN \
    PEEPHOLE_TTY=/tmp/answers bash install.sh > /tmp/wizard2.log 2>&1; then
    echo "expected failure"; exit 1
fi
grep -q "at least one" /tmp/wizard2.log
test ! -e /etc/peephole/config.toml

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
```

- [ ] **Step 2: Run it to verify it fails**

Run the smoke test in a container whose glibc is at least the build host's (see "Running the smoke test locally" at the end of this plan).
Expected: FAIL at "wizard: trap only" (`PEEPHOLE_TTY` is unknown, so the install runs unattended with all roles and dies on the missing domain).

- [ ] **Step 3: Implement the question helpers.** In `install.sh`, replace the "Interactive only if a terminal can actually be opened" block and the three functions `prompt`, `prompt_optional`, `has_role` through `toml_safe` with:

```bash
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
```

Remove the later standalone `toml_safe "$PEEPHOLE_DOMAIN"` style calls that the prompts now cover, but keep `toml_safe` for values that arrive preset from the environment: directly after the wizard (Task 2 adds more variables) call it once for each variable that is written into the config.

- [ ] **Step 4: Ask for the roles.** In the "configuration (first install only)" branch replace the `PEEPHOLE_ROLES="${PEEPHOLE_ROLES:-listener,scanner,web}"` line with:

```bash
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
            [ -n "$PEEPHOLE_ROLES" ] || die "enable at least one of trap, scanner and web interface"
        else
            PEEPHOLE_ROLES="listener,scanner,web"
        fi
    fi
```

The wizard must run before anything is installed, so that a refused answer leaves nothing behind: move the whole "configuration (first install only)" question part (everything that calls `prompt`, `prompt_optional` or `ask_yn`, and the `toml_safe` checks) up, directly after the "validate the new binary against the existing config" block and before "install files", guarded by `if [ "$upgrade" -ne 1 ]; then … fi`. The part that writes `${CONFIG_FILE}` stays where it is.

In the trap part, ask about the local proxy and derive listen address and proxies from it:

```bash
    TRAP_LISTEN="0.0.0.0:8080"
    if has_role listener; then
        ask_yn PEEPHOLE_LOCAL_PROXY "Is a reverse proxy on this machine (nginx) in front of the trap?" n
        if [ "$PEEPHOLE_LOCAL_PROXY" = 1 ]; then
            TRAP_LISTEN="127.0.0.1:8080"
            PEEPHOLE_TRUSTED_PROXIES="127.0.0.1/32,::1/128"
        else
            prompt PEEPHOLE_TRUSTED_PROXIES "Trusted proxy CIDRs, comma-separated (X-Forwarded-For is trusted from these)" "10.0.0.0/8"
        fi
    fi
```

and write `echo "trap_listen = \"${TRAP_LISTEN}\""` in place of the fixed `trap_listen = "0.0.0.0:8080"` line (the comment above it becomes `# Trap listener: your reverse proxy sends requests that match no real site here.`). The closing note "Route fallback traffic from HAProxy to the trap listener (0.0.0.0:8080)." becomes `echo "  - Send requests that match no real site to the trap listener (${TRAP_LISTEN:-0.0.0.0:8080}); see the nginx example."`.

- [ ] **Step 5: Run the smoke test**

Expected: the three new sections pass, as do all earlier ones.

- [ ] **Step 6: Lint and commit**

```bash
shellcheck install.sh tests/install-smoke.sh
git add -A
git commit -m "feat(install): ask for the roles and the local proxy; answers testable from a file"
```

---

### Task 2: Cluster questions, remote configuration, closing summary

**Files:**
- Modify: `install.sh`, `tests/install-smoke.sh`

- [ ] **Step 1: Write the failing smoke test** (before `echo "== ok"`):

```bash
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
```

- [ ] **Step 2: Run it to verify it fails**

Expected: FAIL at "scanner in a cluster" (no cluster question; `remote_config` is not written).

- [ ] **Step 3: Implement.** In the question part of `install.sh`, replace the `prompt_optional PEEPHOLE_CLUSTER_NAME …` block with:

```bash
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
```

All later tests of "is this a cluster node" use `[ "${PEEPHOLE_CLUSTER:-0}" = 1 ]` in place of `[ -n "${PEEPHOLE_CLUSTER_NAME:-}" ]`. In the config writer, after the `advertise` lines:

```bash
            if [ "$PEEPHOLE_REMOTE_CONFIG" = 1 ]; then
                echo "remote_config = true   # holders of this node's config key may change pace, cooldown and roles"
            else
                echo "remote_config = false  # only this node's admin interface, CLI and this file change its settings"
            fi
```

After the join attempt, when remote configuration is on, remember the key for the summary:

```bash
        CONFIG_KEY=""
        if [ "$PEEPHOLE_REMOTE_CONFIG" = 1 ]; then
            CONFIG_KEY="$("$INSTALL_BIN" cluster config-key show "$CONFIG_FILE" 2>/dev/null || true)"
        fi
```

(declare `CONFIG_KEY=""` before the first-install branch so upgrades see it empty.) In the closing "Next steps", replace the cluster lines with:

```bash
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
    fi
fi
```

- [ ] **Step 4: Run the smoke test, lint, commit**

```bash
shellcheck install.sh tests/install-smoke.sh
git add -A
git commit -m "feat(install): cluster, join token and remote configuration questions; config key in the summary"
```

---

### Task 3: A reverse-proxy example that fits the answers

**Files:**
- Modify: `install.sh`, `deploy/nginx.example.conf`, `tests/install-smoke.sh`, `README.md`

- [ ] **Step 1: Write the failing smoke test.** In the "wizard: trap only" section add after its `check-config` line:

```bash
grep -q 'default_server' /etc/peephole/nginx.example.conf
grep -q 'proxy_pass http://127.0.0.1:8080' /etc/peephole/nginx.example.conf
grep -q 'X-Forwarded-For \$remote_addr' /etc/peephole/nginx.example.conf
if grep -q 'server_name peephole\|8443\|proxy_add_x_forwarded_for' /etc/peephole/nginx.example.conf; then
    echo "trap-only nginx example has an admin block or a spoofable header"; exit 1
fi
```

In the "fresh install" section (all roles, domain `peephole.test`) add:

```bash
grep -q 'server_name peephole.test;' /etc/peephole/nginx.example.conf
grep -q 'default_server' /etc/peephole/nginx.example.conf
```

and in the "forced upgrade" section:

```bash
echo '# operator note' >> /etc/peephole/nginx.example.conf
```

before the `PEEPHOLE_FORCE=1 bash install.sh` line, and `grep -q '# operator note' /etc/peephole/nginx.example.conf` after it. In the headless scanner section add `test ! -e /etc/peephole/nginx.example.conf`.

- [ ] **Step 2: Run it to verify it fails**

Expected: FAIL at the first new `grep` (the example is the generic file, with the placeholder domain and no catch-all).

- [ ] **Step 3: Generate the example.** In `install.sh` delete the line `install -m 0644 "${src}/deploy/nginx.example.conf" "${CONFIG_DIR}/nginx.example.conf"` and, in the first-install branch after the config file is written and validated, add:

```bash
    # A reverse-proxy example that fits this node: only the roles it runs,
    # with its domain and listen addresses filled in.
    NGINX_EXAMPLE="${CONFIG_DIR}/nginx.example.conf"
    if has_role web || has_role listener; then
        {
            echo "# nginx in front of peephole — generated by install.sh for this node."
            echo "# Copy to /etc/nginx/sites-available/peephole, adjust the certificate"
            echo "# paths, enable it and reload nginx. peephole does not touch nginx itself."
            if has_role web; then
                cat <<NGINX

# --- Admin area and wall of shame (TLS) --------------------------------------
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
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
```

In the closing summary, print the nginx line only when the file exists, and add the steps:

```bash
if [ -e "${CONFIG_DIR}/nginx.example.conf" ]; then
    echo "  - Reverse proxy: an nginx example for this node is in ${CONFIG_DIR}/nginx.example.conf."
    echo "      cp ${CONFIG_DIR}/nginx.example.conf /etc/nginx/sites-available/peephole"
    echo "      ln -s ../sites-available/peephole /etc/nginx/sites-enabled/peephole"
    echo "      (for the admin site: get a certificate first, e.g. certbot certonly --nginx -d ${PEEPHOLE_DOMAIN:-<your-domain>})"
    echo "      nginx -t && systemctl reload nginx"
fi
```

(remove the fixed `nginx example  : …` line from the heredoc above it.)

`deploy/nginx.example.conf` (the generic reference in the repository): append the catch-all block and the commented HTTPS variant from above, with the trap port `8080` and a leading comment `# Catch-all trap: every request for a host name no other server block claims.`; change the file's first comment line to `# peephole behind nginx: admin area (TLS) and catch-all trap. The installer writes a version of this file that fits the node to /etc/peephole/nginx.example.conf.`

- [ ] **Step 4: README.** In "Install", replace the bullet list "The installer:" and the paragraph about `deploy/nginx.example.conf` with:

```markdown
The installer:

- installs prerequisites (`nmap`, `curl`, `ca-certificates`, `sqlite3`),
- downloads and checksum-verifies the latest build,
- installs the binary to `/usr/local/bin/peephole` and the default signature
  rules to `/etc/peephole/rules`,
- asks what this node should do:
  - run a **trap** (record requests that reach no real site), the
    **scanner** (nmap counter-scans), the **web interface** (wall of shame
    and admin area), in any combination,
  - whether a reverse proxy on the same machine fronts the trap, and
    otherwise which proxy addresses to trust,
  - the public domain of the admin area (with the web interface),
  - whether to take part in a **cluster**: node name, addresses, an invite
    token if you have one, and whether holders of this node's **config key**
    may change its settings,
  - optional **MaxMind GeoLite2** credentials
    (<https://www.maxmind.com/en/accounts/current/license-key>),
- writes `/etc/peephole/config.toml` and an nginx example that fits the
  answers to `/etc/peephole/nginx.example.conf`, and installs and starts a
  systemd service.

It does not install or change nginx. The example has a TLS server block for
the admin area (the live scan queue needs `proxy_buffering off` on
`/admin/api/queue`, which the example sets) and a catch-all `default_server`
that sends everything no real site claims to the trap. The catch-all sets
`X-Forwarded-For` to the real peer address, so a client cannot spoof it. If
you front peephole with HAProxy instead, route its fallback backend to the
trap listener and list the proxy in `trusted_proxies`.
```

and extend the unattended example by one line of explanation: "Every question has a variable (`PEEPHOLE_ROLES`, `PEEPHOLE_LOCAL_PROXY`, `PEEPHOLE_CLUSTER`, `PEEPHOLE_CLUSTER_NAME`, `PEEPHOLE_JOIN_TOKEN`, `PEEPHOLE_REMOTE_CONFIG`, …; see the head of `install.sh`)." Update the header comment of `install.sh` with the new variables from the table above.

- [ ] **Step 5: Run the smoke test, lint, commit**

```bash
shellcheck install.sh tests/install-smoke.sh
git add -A
git commit -m "feat(install): nginx example generated for the node's roles, with a catch-all trap"
```

---

## Running the smoke test locally

CI runs `tests/install-smoke.sh` in `ubuntu:24.04` with a binary built on the runner. On a development machine whose glibc is newer than that image's, use an image at least as new as the host (or a musl build via `PEEPHOLE_BIN`):

```bash
PEEPHOLE_VERSION=test1 cargo build --release
podman run --rm -v "$PWD":/src:Z -w /src docker.io/library/ubuntu:26.04 bash tests/install-smoke.sh
```

If no suitable image is available, at least run `bash -n install.sh`, `shellcheck`, and the wizard sections by hand in a throwaway container.
