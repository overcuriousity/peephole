use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_peephole"))
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
    let out = bin()
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

    let bad = dir.path().join("bad.toml");
    std::fs::write(&bad, "trap_listen = 12\n").unwrap();
    let out = bin()
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
