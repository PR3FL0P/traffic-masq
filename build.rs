use std::{env, path::Path, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let root = env::var("CARGO_MANIFEST_DIR").ok()?;
    let top = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&root)
        .output()
        .ok()?;
    if !top.status.success()
        || Path::new(String::from_utf8_lossy(&top.stdout).trim())
            .canonicalize()
            .ok()?
            != Path::new(&root).canonicalize().ok()?
    {
        return None;
    }
    let output = Command::new("git")
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    for key in ["TRAFFIC_MASQ_BUILD_REVISION", "TRAFFIC_MASQ_BUILD_DIRTY"] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    // Explicit source paths keep the target directory out of rebuild detection.
    for path in [
        "build.rs",
        "src",
        "crates",
        "Cargo.toml",
        "Cargo.lock",
        "docs",
        "examples",
        "packaging",
        "README.md",
        "SECURITY.md",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    // Resolve paths through Git to support linked worktrees as well as checkouts.
    for name in ["HEAD", "index", "refs", "packed-refs"] {
        if let Some(path) = git(&["rev-parse", "--git-path", name]) {
            if Path::new(&path).exists() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
    let explicit = env::var("TRAFFIC_MASQ_BUILD_REVISION").ok();
    let revision = explicit
        .clone()
        .or_else(|| git(&["rev-parse", "--verify", "HEAD"]));
    let revision = revision
        .filter(|value| {
            matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .unwrap_or_else(|| "unknown".into());
    let dirty = env::var("TRAFFIC_MASQ_BUILD_DIRTY")
        .ok()
        .filter(|value| matches!(value.as_str(), "true" | "false" | "unknown"))
        .unwrap_or_else(|| {
            if explicit.is_some() {
                return "unknown".into();
            }
            git(&["status", "--porcelain", "--untracked-files=normal"])
                .map(|status| (!status.is_empty()).to_string())
                .unwrap_or_else(|| "unknown".into())
        });
    println!("cargo:rustc-env=TRAFFIC_MASQ_BUILD_REVISION={revision}");
    println!("cargo:rustc-env=TRAFFIC_MASQ_BUILD_DIRTY={dirty}");
}
