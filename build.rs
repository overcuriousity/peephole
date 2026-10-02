//! Concatenates the CSS layers into one embedded stylesheet, stamps the
//! asset URLs with a content hash, and bakes the release version and the
//! source commit in.
use std::path::Path;
use std::process::Command;

fn main() {
    build_stylesheet();
    stamp_assets();
    // The build's name: the commit for rolling builds, the tag for versioned
    // releases (both set by CI), "dev" otherwise.
    println!("cargo:rerun-if-env-changed=PEEPHOLE_VERSION");
    let version = std::env::var("PEEPHOLE_VERSION").unwrap_or_else(|_| "dev".into());
    println!("cargo:rustc-env=PEEPHOLE_VERSION={version}");
    println!("cargo:rustc-env=PEEPHOLE_COMMIT={}", commit());
}

/// The commit the binary is built from (12 hex digits): `PEEPHOLE_COMMIT`,
/// else `GITHUB_SHA` (CI), else `git rev-parse HEAD`, else "unknown" (a
/// source tree without git).
fn commit() -> String {
    println!("cargo:rerun-if-env-changed=PEEPHOLE_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let full = std::env::var("PEEPHOLE_COMMIT")
        .ok()
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            // Rebuild when HEAD moves (a commit, a checkout): the reflog grows
            // with every move, the branch ref may be packed. Only existing
            // files: cargo reruns the script every time for a missing one.
            let mut watch = vec![
                "HEAD".to_string(),
                "logs/HEAD".to_string(),
                "packed-refs".to_string(),
            ];
            watch.extend(git(&["symbolic-ref", "-q", "HEAD"]));
            for p in &watch {
                if let Some(path) = git(&["rev-parse", "--git-path", p])
                    && Path::new(&path).exists()
                {
                    println!("cargo:rerun-if-changed={path}");
                }
            }
            git(&["rev-parse", "HEAD"])
        });
    match full {
        Some(s) if s.chars().all(|c| c.is_ascii_hexdigit()) => s.chars().take(12).collect(),
        _ => "unknown".into(),
    }
}

/// `assets/app.css` = `assets/css/*.css` in filename order (numeric prefixes
/// order the cascade: tokens first). Generated and gitignored.
fn build_stylesheet() {
    println!("cargo:rerun-if-changed=assets/css");
    let dir = Path::new("assets/css");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("assets/css")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".css"))
        .collect();
    names.sort();
    let mut out = String::new();
    for name in &names {
        let body = std::fs::read_to_string(dir.join(name))
            .unwrap_or_else(|e| panic!("assets/css/{name}: {e}"));
        out.push_str(&format!("/* ===== {name} ===== */\n{body}\n"));
    }
    let dest = Path::new("assets/app.css");
    // Only write when changed: cargo watches this file's mtime.
    if std::fs::read_to_string(dest).ok().as_deref() != Some(out.as_str()) {
        std::fs::write(dest, &out).expect("assets/app.css");
    }
}

/// FNV-1a over the files pages reference by URL. Cache-busting query stamp.
fn stamp_assets() {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for name in [
        "assets/app.css",
        "assets/js/app.js",
        "assets/js/charts.js",
        "assets/js/theme.js",
        "assets/world.svg",
    ] {
        println!("cargo:rerun-if-changed={name}");
        for b in std::fs::read(name).unwrap_or_default() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    println!("cargo:rustc-env=ASSET_STAMP={h:x}");
}
