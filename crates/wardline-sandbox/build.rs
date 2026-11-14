use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn locate_zig() -> PathBuf {
    if let Ok(path) = env::var("ZIG") {
        let p = PathBuf::from(path);
        if p.exists() {
            return p;
        }
    }
    if let Ok(paths) = env::var("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join("zig.exe");
            if candidate.exists() {
                return candidate;
            }
            let unix = dir.join("zig");
            if unix.exists() {
                return unix;
            }
        }
    }
    if let Ok(local_app) = env::var("LOCALAPPDATA") {
        let pkgs = Path::new(&local_app)
            .join("Microsoft")
            .join("WinGet")
            .join("Packages");
        if let Ok(entries) = std::fs::read_dir(pkgs) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("zig.zig") {
                    if let Ok(sub) = std::fs::read_dir(entry.path()) {
                        for child in sub.flatten() {
                            let exe = child.path().join("zig.exe");
                            if exe.exists() {
                                return exe;
                            }
                        }
                    }
                }
            }
        }
    }
    panic!("zig executable not found on PATH, ZIG env var, or WinGet packages");
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let platforms_dir = workspace_root.join("platforms");

    println!(
        "cargo:rerun-if-changed={}",
        platforms_dir.join("common").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        platforms_dir.join("win-x64").display()
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let opt_flag = if profile == "release" {
        "-OReleaseFast"
    } else {
        "-ODebug"
    };

    let (zig_target, engine_rel, lib_name, lib_file) = match target_arch.as_str() {
        "x86_64" => (
            "x86_64-windows-msvc",
            "win-x64/engine_x64.zig",
            "wardline_engine_x64",
            "wardline_engine_x64.lib",
        ),
        other => panic!(
            "wardline-x64 only targets x86_64 Windows (got {other}); use wardline-arm64 for ARM64"
        ),
    };

    let zig_exe = locate_zig();
    let engine_path = platforms_dir.join(engine_rel);
    let common_path = platforms_dir.join("common/common.zig");
    let out_lib = out_dir.join(lib_file);
    let cache_dir = out_dir.join("zig-cache");

    let root_arg = format!("-Mroot={}", engine_path.display());
    let common_arg = format!("-Mcommon={}", common_path.display());
    let emit_arg = format!("-femit-bin={}", out_lib.display());

    let status = Command::new(&zig_exe)
        .args([
            "build-lib",
            "-target",
            zig_target,
            opt_flag,
            "-lc",
            "--cache-dir",
        ])
        .arg(&cache_dir)
        .args(["--dep", "common", &root_arg, &common_arg, &emit_arg])
        .status()
        .expect("failed to execute zig build-lib");

    if !status.success() {
        panic!("zig build-lib failed for {zig_target} with status {status}");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static={lib_name}");
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=userenv");
    println!("cargo:rustc-link-lib=kernel32");
}
