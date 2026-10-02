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
    let out = run(&["admin", "setup-token"]);
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
