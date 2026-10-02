use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_peephole"))
}

/// A stand-in `nmap` so the test does not depend on nmap being installed
/// (CI runners do not have it). `check-config` only runs `nmap --version`.
fn fake_nmap(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("fake-nmap");
    std::fs::write(&p, "#!/bin/sh\necho 'Nmap version 7.99 ( fake )'\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

#[test]
fn version_flag_prints_version() {
    let out = bin().arg("--version").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("peephole "), "{s}");
    assert!(s.trim().len() > "peephole ".len());
}

#[test]
fn check_config_accepts_example_and_rejects_garbage() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.toml");
    std::fs::write(
        &good,
        format!(
            r#"
trap_listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
database_path = "{d}/t.db"
data_dir = "{d}"
rules_dir = "rules"
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
[maxmind]
account_id = "1"
license_key = "k"
"#,
            d = dir.path().display()
        ),
    )
    .unwrap();
    let nmap = fake_nmap(dir.path());
    let out = bin()
        .env("PEEPHOLE_NMAP_PATH", &nmap)
        .args(["check-config", good.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("ok:") && stdout.contains("rules"),
        "{stdout}"
    );
    // Optional keys the config leaves out are pointed out, so operators learn
    // about new settings on upgrade.
    assert!(
        stdout.contains("note: optional") && stdout.contains("secure_cookies"),
        "{stdout}"
    );
    assert!(stdout.contains("[scan]"), "{stdout}");

    let bad = dir.path().join("bad.toml");
    std::fs::write(&bad, "trap_listen = 12\n").unwrap();
    let out = bin()
        .env("PEEPHOLE_NMAP_PATH", &nmap)
        .args(["check-config", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("config"));

    let out = bin()
        .args(["check-config", "/nonexistent/x.toml"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

/// Nodes without the scanner role don't need nmap, and nodes without the
/// web role need no [webauthn]; neither needs [maxmind].
#[test]
fn check_config_listener_only_needs_no_nmap_or_webauthn() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
trap_listen = "127.0.0.1:0"
database_path = "{d}/t.db"
data_dir = "{d}"
rules_dir = "rules"
[roles]
scanner = false
web = false
"#,
            d = dir.path().display()
        ),
    )
    .unwrap();
    let out = bin()
        .env("PEEPHOLE_NMAP_PATH", "/nonexistent/nmap")
        .args(["check-config", cfg.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("roles: listener"), "{stdout}");
    assert!(!stdout.contains("webauthn"), "{stdout}");
}

#[test]
fn cluster_id_creates_key_once_and_prints_it() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
database_path = "{d}/t.db"
data_dir = "{d}"
[roles]
listener = false
web = false
[cluster]
node_name = "n1"
listen = "127.0.0.1:0"
"#,
            d = dir.path().display()
        ),
    )
    .unwrap();
    let id = || {
        let out = bin()
            .args(["cluster", "id", cfg.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let first = id();
    assert!(first.starts_with("ed25519:"), "{first}");
    assert_eq!(first, id(), "key is created once, then reused");
    assert!(dir.path().join("node.key").exists());
}

#[test]
fn cluster_invite_and_members_work_headless() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
database_path = "{d}/t.db"
data_dir = "{d}"
[roles]
listener = false
web = false
[cluster]
node_name = "scanner-1"
listen = "127.0.0.1:0"
advertise = "scanner-1.example:7443"
"#,
            d = dir.path().display()
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        let out = bin()
            .arg("cluster")
            .args(args)
            .arg(cfg.to_str().unwrap())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let token = run(&["invite", "--ttl", "2"]);
    assert!(token.starts_with("peephole1:"), "{token}");
    let members = run(&["members"]);
    assert!(
        members.contains("scanner-1") && members.contains("(this node)"),
        "{members}"
    );
    assert!(members.contains("roles=scanner"), "{members}");
    let status = run(&["status"]);
    assert!(status.contains("history   full"), "{status}");
    // The config key exists only with remote configuration switched on.
    let out = bin()
        .args(["cluster", "config-key", "show"])
        .arg(cfg.to_str().unwrap())
        .output()
        .unwrap();
    assert!(!out.status.success(), "locked node has no usable key");
    let text = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(
        &cfg,
        text.replace(
            "node_name = \"scanner-1\"",
            "node_name = \"scanner-1\"\nremote_config = true",
        ),
    )
    .unwrap();
    let shown = run(&["config-key", "show"]);
    assert!(shown.starts_with("peephole-cfg1:"), "{shown}");
    let rotated = run(&["config-key", "rotate"]);
    assert!(
        rotated.starts_with("peephole-cfg1:") && rotated != shown,
        "{rotated}"
    );
    assert_eq!(run(&["config-key", "show"]), rotated);
}

#[test]
fn setup_token_and_vacuum_from_the_shell() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "{d}/t.db"
data_dir = "{d}"
[roles]
listener = false
scanner = false
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
"#,
            d = dir.path().display()
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        bin()
            .args(args)
            .arg(cfg.to_str().unwrap())
            .output()
            .unwrap()
    };
    let out = run(&["admin", "reset-token"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("/enroll") && stdout.contains("24 hours"),
        "{stdout}"
    );
    let out = run(&["db", "vacuum"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("done:"), "{stdout}");
    let out = run(&["admin", "nonsense"]);
    assert!(!out.status.success());
}

#[test]
fn settings_are_shown_set_and_reset_from_the_shell() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
trap_listen = "127.0.0.1:1"
rules_dir = "rules"
database_path = "{d}/t.db"
data_dir = "{d}"
[roles]
scanner = false
web = false
"#,
            d = dir.path().display()
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        bin()
            .arg("settings")
            .args(args)
            .arg(cfg.to_str().unwrap())
            .output()
            .unwrap()
    };
    let text = |o: &std::process::Output| {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    };
    let out = run(&["set", "scan.rescan_cooldown_hours", "48"]);
    assert!(out.status.success(), "{}", text(&out));
    let shown = text(&run(&["show"]));
    assert!(
        shown.contains("scan.rescan_cooldown_hours")
            && shown.contains("48")
            && shown.contains("override"),
        "{shown}"
    );
    // The only role cannot be switched off; an unknown key is refused.
    let out = run(&["set", "roles.listener", "false"]);
    assert!(!out.status.success());
    assert!(text(&out).contains("at least one role"), "{}", text(&out));
    assert!(!run(&["set", "scan.level_argv", "x"]).status.success());
    let out = run(&["reset", "scan.rescan_cooldown_hours"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!text(&run(&["show"])).contains("override"));
}

#[test]
fn admin_reset_token_replaces_the_setup_token() {
    let dir = tempfile::tempdir().unwrap();
    let write = |web: bool| {
        let cfg = dir.path().join(format!("c{web}.toml"));
        std::fs::write(
            &cfg,
            format!(
                r#"
trap_listen = "127.0.0.1:1"
admin_listen = "127.0.0.1:2"
rules_dir = "rules"
database_path = "{d}/t.db"
data_dir = "{d}"
[roles]
scanner = false
web = {web}
[webauthn]
rp_id = "peephole.example.net"
origin = "https://peephole.example.net"
rp_name = "peephole"
"#,
                d = dir.path().display()
            ),
        )
        .unwrap();
        cfg
    };
    let cfg = write(true);
    let reset = |cfg: &std::path::Path| {
        bin()
            .args(["admin", "reset-token"])
            .arg(cfg)
            .output()
            .unwrap()
    };
    let token = |o: &std::process::Output| {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(out.contains("enter this one-time token"), "{out}");
        out.split_whitespace()
            .find(|w| w.len() == 36 && w.matches('-').count() == 4)
            .unwrap_or_else(|| panic!("no token in {out}"))
            .to_string()
    };
    let first = token(&reset(&cfg));
    let second = token(&reset(&cfg));
    assert_ne!(first, second);
    // Only the newest token is valid.
    let stored = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let store = peephole::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        store
            .intel_get("webauthn_setup_token_hash")
            .await
            .unwrap()
            .unwrap()
    });
    use sha2::Digest;
    let hash = |t: &str| data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(t.as_bytes()));
    assert_eq!(stored, hash(&second));
    // A node without the web interface has no use for one.
    let out = reset(&write(false));
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no web interface"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `cluster status` says how much history this node keeps and where it
/// starts per member.
#[tokio::test]
async fn cluster_status_shows_the_history_kept() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
retention_days = 7
database_path = "{d}/t.db"
data_dir = "{d}"
[roles]
listener = false
web = false
[cluster]
node_name = "window-1"
listen = "127.0.0.1:0"
advertise = "window-1.example:7443"
"#,
            d = dir.path().display()
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        let out = bin()
            .arg("cluster")
            .args(args)
            .arg(cfg.to_str().unwrap())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    run(&["invite", "--ttl", "2"]);
    let id = run(&["id"]);
    let id = peephole::cluster::identity::NodeId::parse(id.trim()).unwrap();
    let store = peephole::store::Store::connect(&dir.path().join("t.db"))
        .await
        .unwrap();
    sqlx::query("INSERT INTO repl_floors (origin, seq) VALUES (?, 3)")
        .bind(&id.0[..])
        .execute(&store.pool)
        .await
        .unwrap();
    let status = run(&["status"]);
    assert!(status.contains("history   keeps 7 days"), "{status}");
    assert!(status.contains("held from seq 3"), "{status}");
}
