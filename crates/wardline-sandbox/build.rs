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

    println!("cargo:rerun-if-env-changed=WARDLINE_PREBUILT_ENGINE_DIR");
    println!("cargo:rerun-if-env-changed=ZIG");
    for sub in ["common", "win-arm64", "win-x64", "linux", "macos", "bsd"] {
        let p = platforms_dir.join(sub);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let opt_flag = if profile == "release" {
        "-OReleaseFast"
    } else {
        "-ODebug"
    };

    let (zig_target, engine_rel, lib_name, lib_file, sys_libs): (
        &str,
        &str,
        &str,
        &str,
        &[&str],
    ) = match (target_os.as_str(), target_arch.as_str(), target_env.as_str()) {
        ("windows", "aarch64", "msvc") => (
            "aarch64-windows-msvc",
            "win-arm64/engine_arm64.zig",
            "wardline_engine_arm64",
            "wardline_engine_arm64.lib",
            &["advapi32", "userenv", "kernel32"],
        ),
        ("windows", "aarch64", _) => (
            "aarch64-windows-gnu",
            "win-arm64/engine_arm64.zig",
            "wardline_engine_arm64",
            "libwardline_engine_arm64.a",
            &["advapi32", "userenv", "kernel32"],
        ),
        ("windows", "x86_64", "msvc") => (
            "x86_64-windows-msvc",
            "win-x64/engine_x64.zig",
            "wardline_engine_x64",
            "wardline_engine_x64.lib",
            &["advapi32", "userenv", "kernel32"],
        ),
        ("windows", "x86_64", _) => (
            "x86_64-windows-gnu",
            "win-x64/engine_x64.zig",
            "wardline_engine_x64",
            "libwardline_engine_x64.a",
            &["advapi32", "userenv", "kernel32"],
        ),
        ("linux", "aarch64", "musl") => (
            "aarch64-linux-musl",
            "linux/engine_linux.zig",
            "wardline_engine_arm64",
            "libwardline_engine_arm64.a",
            &[],
        ),
        ("linux", "aarch64", _) => (
            "aarch64-linux-gnu",
            "linux/engine_linux.zig",
            "wardline_engine_arm64",
            "libwardline_engine_arm64.a",
            &[],
        ),
        ("linux", "x86_64", "musl") => (
            "x86_64-linux-musl",
            "linux/engine_linux.zig",
            "wardline_engine_x64",
            "libwardline_engine_x64.a",
            &[],
        ),
        ("linux", "x86_64", _) => (
            "x86_64-linux-gnu",
            "linux/engine_linux.zig",
            "wardline_engine_x64",
            "libwardline_engine_x64.a",
            &[],
        ),
        ("macos", "aarch64", _) => (
            "aarch64-macos",
            "macos/engine_macos.zig",
            "wardline_engine_arm64",
            "libwardline_engine_arm64.a",
            &[],
        ),
        ("macos", "x86_64", _) => (
            "x86_64-macos",
            "macos/engine_macos.zig",
            "wardline_engine_x64",
            "libwardline_engine_x64.a",
            &[],
        ),
        ("freebsd", "aarch64", _) => (
            "aarch64-freebsd",
            "bsd/engine_bsd.zig",
            "wardline_engine_arm64",
            "libwardline_engine_arm64.a",
            &[],
        ),
        ("freebsd", "x86_64", _) => (
            "x86_64-freebsd",
            "bsd/engine_bsd.zig",
            "wardline_engine_x64",
            "libwardline_engine_x64.a",
            &[],
        ),
        other => panic!("unsupported target OS/arch/env combination: {other:?}"),
    };

    let mut linked_prebuilt = false;
    if let Ok(prebuilt_dir) = env::var("WARDLINE_PREBUILT_ENGINE_DIR") {
        let pdir = PathBuf::from(prebuilt_dir);
        let candidate = pdir.join(lib_file);
        if candidate.exists() {
            println!("cargo:rustc-link-search=native={}", pdir.display());
            println!("cargo:rustc-link-lib=static={lib_name}");
            linked_prebuilt = true;
        }
    }

    if !linked_prebuilt {
        let engine_path = platforms_dir.join(engine_rel);
        if !engine_path.exists() {
            panic!(
                "missing Zig engine source '{}' for target ({target_os}, {target_arch})",
                engine_path.display()
            );
        }
        let zig_exe = locate_zig();
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
    }

    for lib in sys_libs {
        println!("cargo:rustc-link-lib={lib}");
    }
}
