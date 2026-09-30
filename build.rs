//! Concatenates the CSS layers into one embedded stylesheet, stamps the
//! asset URLs with a content hash, and bakes the release version in.
use std::path::Path;

fn main() {
    build_stylesheet();
    stamp_assets();
    println!("cargo:rerun-if-env-changed=PEEPHOLE_VERSION");
    let version = std::env::var("PEEPHOLE_VERSION").unwrap_or_else(|_| "dev".into());
    println!("cargo:rustc-env=PEEPHOLE_VERSION={version}");
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
