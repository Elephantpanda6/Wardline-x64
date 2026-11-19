use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use wardline_core::{IsolationLevel, TargetArch};
use wardline_sandbox::{
    engine_identity, harden_current_process_dacl, probe_capabilities, set_owner_only_dacl,
    spawn_isolated, EngineStatus, SpawnConfig,
};

#[cfg(windows)]
use wardline_sandbox::create_hardened_pipe;

fn run_child_probe(mode: &str) -> i32 {
    match mode {
        "echo_env" => {
            let leak = std::env::var("WARDLINE_PARENT_SECRET").unwrap_or_default();
            let marker = std::env::var("WARDLINE_ALLOWED_VAR").unwrap_or_default();
            println!("leak={leak};marker={marker}");
            if leak.is_empty() && marker == "safe_ok" {
                0
            } else {
                2
            }
        }
        "net_block" => {
            let host_port: u16 = std::env::var("WARDLINE_HOST_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(9);
            let ext_res = TcpStream::connect_timeout(
                &"1.1.1.1:80".parse().unwrap(),
                Duration::from_millis(200),
            );
            let lo_res = TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], host_port)),
                Duration::from_millis(200),
            );
            match (ext_res, lo_res) {
                (Err(e1), Err(e2)) if e1.kind() == ErrorKind::PermissionDenied => {
                    println!(
                        "net_blocked=1 ext_err={} lo_kind={:?}",
                        e1.raw_os_error().unwrap_or(-1),
                        e2.kind()
                    );
                    0
                }
                #[cfg(unix)]
                (Err(e1), Err(e2)) => {
                    println!(
                        "net_blocked=1 ext_kind={:?} ext_err={} lo_kind={:?}",
                        e1.kind(),
                        e1.raw_os_error().unwrap_or(-1),
                        e2.kind()
                    );
                    0
                }
                other => {
                    eprintln!("SECURITY FAILURE inside L1 sandbox: {other:?}");
                    99
                }
            }
        }
        "fs_escape_check" => {
            let denied = std::env::var("WARDLINE_DENIED_FILE").unwrap();
            let allowed = std::env::var("WARDLINE_ALLOWED_DIR").unwrap();
            let read_denied = std::fs::read_to_string(&denied);
            let write_ok = std::fs::write(PathBuf::from(&allowed).join("ok.txt"), b"hello-ac");
            match (read_denied, write_ok) {
                (Err(e), Ok(())) => {
                    println!("fs_isolated=1 denied_err={}", e.raw_os_error().unwrap_or(-1));
                    0
                }
                (Ok(_), _) => {
                    eprintln!("SECURITY FAILURE: L1 sandbox read ungranted file!");
                    98
                }
                (Err(e1), Err(e2)) => {
                    eprintln!("unexpected io error: denied={e1} allowed={e2}");
                    97
                }
            }
        }
        "sleep_hang" => {
            println!("child_sleeping");
            std::thread::sleep(Duration::from_secs(10));
            0
        }
        "alloc_oom" => {
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            for _ in 0..128 {
                let mut v = vec![0xA5u8; 1024 * 1024];
                v[0] = 1;
                chunks.push(v);
            }
            0
        }
        other => {
            eprintln!("unknown probe mode {other}");
            42
        }
    }
}

fn test_base_cfg(mode: &str) -> SpawnConfig {
    let exe = std::env::current_exe().unwrap();
    #[cfg(windows)]
    let (cmdline, env_pairs) = (
        format!("\"{}\"", exe.display()),
        vec![
            ("WARDLINE_PROBE_MODE".into(), mode.into()),
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("PATH".into(), r"C:\Windows\System32".into()),
        ],
    );
    #[cfg(unix)]
    let (cmdline, env_pairs) = (
        exe.to_string_lossy().into_owned(),
        vec![
            ("WARDLINE_PROBE_MODE".into(), mode.into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
        ],
    );
    SpawnConfig {
        executable: exe.to_string_lossy().into_owned(),
        cmdline,
        env_pairs,
        timeout_ms: 5_000,
        max_memory_bytes: 256 * 1024 * 1024,
        max_processes: 8,
        cpu_rate_percent: 80,
        ..Default::default()
    }
}

#[cfg(windows)]
fn run_windows_suite() {
    let (arch, abi) = engine_identity();
    assert_eq!(arch, TargetArch::host());
    assert_eq!(abi, 1);

    let caps = probe_capabilities().expect("probe_capabilities");
    assert_eq!(caps.os_name(), "windows");
    assert_eq!(caps.appcontainer_supported, 1);
    assert_eq!(caps.job_object_iocp_supported, 1);
    println!("[PASS] probe_capabilities os_build={}", caps.os_build_number);

    std::env::set_var("WARDLINE_PARENT_SECRET", "top_secret_should_not_leak");
    let mut cfg_env = test_base_cfg("echo_env");
    cfg_env.isolation = IsolationLevel::L0;
    cfg_env
        .env_pairs
        .push(("WARDLINE_ALLOWED_VAR".into(), "safe_ok".into()));
    let out_env = spawn_isolated(&cfg_env);
    let stdout_env = String::from_utf8_lossy(&out_env.stdout);
    assert_eq!(out_env.status, EngineStatus::Ok, "env test: {out_env:?}");
    assert_eq!(out_env.exit_code, 0, "stdout={stdout_env}");
    assert!(stdout_env.contains("leak=;marker=safe_ok"), "{stdout_env}");
    println!("[PASS] L0 RestrictedJob env isolation + handle sanitization");

    let host_listener = TcpListener::bind("127.0.0.1:0").expect("bind host listener");
    let host_port = host_listener.local_addr().unwrap().port();
    let mut cfg_net = test_base_cfg("net_block");
    cfg_net.isolation = IsolationLevel::L1;
    cfg_net.container_name = format!("wardline.test.net.{}", std::process::id());
    cfg_net
        .env_pairs
        .push(("WARDLINE_HOST_PORT".into(), host_port.to_string()));
    let out_net = spawn_isolated(&cfg_net);
    drop(host_listener);
    let stdout_net = String::from_utf8_lossy(&out_net.stdout);
    assert_eq!(out_net.status, EngineStatus::Ok, "net test: {out_net:?}");
    assert_eq!(
        out_net.exit_code,
        0,
        "stdout={stdout_net} stderr={}",
        String::from_utf8_lossy(&out_net.stderr)
    );
    assert!(stdout_net.contains("net_blocked=1"), "{stdout_net}");
    println!("[PASS] L1 AppContainer zero-capability kernel network denial: {stdout_net}");

    let sandbox_root = std::env::temp_dir().join(format!("wardline_ac_fs_{}", std::process::id()));
    let secret_dir = sandbox_root.join("outside_secret");
    let work_dir = sandbox_root.join("granted_work");
    let _ = std::fs::remove_dir_all(&sandbox_root);
    std::fs::create_dir_all(&secret_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    let secret_file = secret_dir.join("key.txt");
    std::fs::write(&secret_file, b"TOP_SECRET").unwrap();
    set_owner_only_dacl(secret_dir.to_str().unwrap(), true).unwrap();
    set_owner_only_dacl(secret_file.to_str().unwrap(), false).unwrap();

    let mut cfg_fs = test_base_cfg("fs_escape_check");
    cfg_fs.isolation = IsolationLevel::L1;
    cfg_fs.container_name = format!("wardline.test.fs.{}", std::process::id());
    cfg_fs.rw_paths = vec![work_dir.to_string_lossy().into_owned()];
    cfg_fs.env_pairs.push((
        "WARDLINE_DENIED_FILE".into(),
        secret_file.to_string_lossy().into_owned(),
    ));
    cfg_fs.env_pairs.push((
        "WARDLINE_ALLOWED_DIR".into(),
        work_dir.to_string_lossy().into_owned(),
    ));
    let out_fs = spawn_isolated(&cfg_fs);
    let stdout_fs = String::from_utf8_lossy(&out_fs.stdout);
    assert_eq!(out_fs.status, EngineStatus::Ok, "fs test: {out_fs:?}");
    assert_eq!(
        out_fs.exit_code,
        0,
        "stdout={stdout_fs} stderr={}",
        String::from_utf8_lossy(&out_fs.stderr)
    );
    assert!(stdout_fs.contains("fs_isolated=1"), "{stdout_fs}");
    assert_eq!(std::fs::read(work_dir.join("ok.txt")).unwrap(), b"hello-ac");
    let _ = std::fs::remove_dir_all(&sandbox_root);
    println!("[PASS] L1 AppContainer filesystem isolation: {stdout_fs}");

    let mut cfg_to = test_base_cfg("sleep_hang");
    cfg_to.isolation = IsolationLevel::L0;
    cfg_to.timeout_ms = 300;
    let out_to = spawn_isolated(&cfg_to);
    assert!(out_to.timed_out, "expected timeout kill, got {out_to:?}");
    assert_eq!(out_to.status, EngineStatus::TimeoutKilled);
    println!("[PASS] JobObject IOCP timeout reaper killed hanging child cleanly");

    let mut cfg_oom = test_base_cfg("alloc_oom");
    cfg_oom.isolation = IsolationLevel::L0;
    cfg_oom.max_memory_bytes = 24 * 1024 * 1024;
    let out_oom = spawn_isolated(&cfg_oom);
    assert!(
        out_oom.oom_killed || out_oom.exit_code != 0,
        "expected OOM / non-zero exit under 24 MiB job cap, got {out_oom:?}"
    );
    println!(
        "[PASS] JobObject memory cap enforced: oom_killed={} exit={} peak={} bytes",
        out_oom.oom_killed, out_oom.exit_code, out_oom.peak_memory_bytes
    );

    let pipe_name = format!(r"\\.\pipe\wardline_test_{}", std::process::id());
    let _h1 = create_hardened_pipe(&pipe_name).expect("first pipe succeeds");
    assert!(
        create_hardened_pipe(&pipe_name).is_err(),
        "second pipe instance on same name must be rejected by FILE_FLAG_FIRST_PIPE_INSTANCE"
    );
    harden_current_process_dacl().expect("harden_current_process_dacl succeeds");
    println!("[PASS] FILE_FLAG_FIRST_PIPE_INSTANCE anti-squatting & process DACL hardened");

    let cfg_sys = SpawnConfig {
        executable: r"C:\Windows\System32\whoami.exe".into(),
        cmdline: "\"C:\\Windows\\System32\\whoami.exe\"".into(),
        working_dir: r"C:\Windows\System32".into(),
        env_pairs: vec![
            ("PATH".into(), r"C:\Windows\System32".into()),
            ("SystemRoot".into(), r"C:\Windows".into()),
        ],
        container_name: format!("wardline.test.sys.{}", std::process::id()),
        isolation: IsolationLevel::L1,
        timeout_ms: 5_000,
        max_memory_bytes: 128 * 1024 * 1024,
        max_processes: 8,
        cpu_rate_percent: 80,
        enable_acg: true,
        allow_arm64ec: true,
        ..Default::default()
    };
    let out_sys = spawn_isolated(&cfg_sys);
    let stdout_sys = String::from_utf8_lossy(&out_sys.stdout);
    assert_eq!(out_sys.status, EngineStatus::Ok, "sys test: {out_sys:?}");
    assert_eq!(
        out_sys.exit_code,
        0,
        "stdout={stdout_sys} stderr={}",
        String::from_utf8_lossy(&out_sys.stderr)
    );
    assert!(out_sys.acg_applied);
    assert!(!stdout_sys.trim().is_empty(), "{stdout_sys}");
    println!(
        "[PASS] L1 AppContainer System32 whoami.exe exit=0 (user={}) isolated desktop + ACG",
        stdout_sys.trim()
    );
}

#[cfg(unix)]
fn run_unix_suite() {
    use std::os::unix::fs::PermissionsExt;

    let (arch, abi) = engine_identity();
    assert_eq!(arch, TargetArch::host());
    assert_eq!(abi, 1);

    let caps = probe_capabilities().expect("probe_capabilities");
    assert!(caps.os_kind >= 2);
    assert!(caps.page_size >= 4096);
    assert_eq!(caps.job_object_iocp_supported, 1);
    println!(
        "[PASS] probe_capabilities os={} os_build={} page_size={} l1_supported={}",
        caps.os_name(),
        caps.os_build_number,
        caps.page_size,
        caps.appcontainer_supported
    );

    std::env::set_var("WARDLINE_PARENT_SECRET", "top_secret_should_not_leak");
    let mut cfg_env = test_base_cfg("echo_env");
    cfg_env.isolation = IsolationLevel::L0;
    cfg_env
        .env_pairs
        .push(("WARDLINE_ALLOWED_VAR".into(), "safe_ok".into()));
    let out_env = spawn_isolated(&cfg_env);
    let stdout_env = String::from_utf8_lossy(&out_env.stdout);
    assert_eq!(out_env.status, EngineStatus::Ok, "env test: {out_env:?}");
    assert_eq!(out_env.exit_code, 0, "stdout={stdout_env}");
    assert!(stdout_env.contains("leak=;marker=safe_ok"), "{stdout_env}");
    println!("[PASS] POSIX L0 env isolation + FD sanitization");

    let host_listener = TcpListener::bind("127.0.0.1:0").expect("bind host listener");
    let host_port = host_listener.local_addr().unwrap().port();
    let mut cfg_net = test_base_cfg("net_block");
    cfg_net.isolation = IsolationLevel::L1;
    cfg_net
        .env_pairs
        .push(("WARDLINE_HOST_PORT".into(), host_port.to_string()));
    let out_net = spawn_isolated(&cfg_net);
    drop(host_listener);
    let stdout_net = String::from_utf8_lossy(&out_net.stdout);
    assert_eq!(out_net.status, EngineStatus::Ok, "net test: {out_net:?}");
    assert_eq!(
        out_net.exit_code,
        0,
        "stdout={stdout_net} stderr={}",
        String::from_utf8_lossy(&out_net.stderr)
    );
    assert!(stdout_net.contains("net_blocked=1"), "{stdout_net}");
    println!("[PASS] POSIX L1 kernel network denial: {}", stdout_net.trim());

    let sandbox_root = std::env::temp_dir().join(format!("wardline_unix_fs_{}", std::process::id()));
    let secret_dir = sandbox_root.join("outside_secret");
    let work_dir = sandbox_root.join("granted_work");
    let _ = std::fs::remove_dir_all(&sandbox_root);
    std::fs::create_dir_all(&secret_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    let secret_file = secret_dir.join("key.txt");
    std::fs::write(&secret_file, b"TOP_SECRET").unwrap();
    set_owner_only_dacl(secret_dir.to_str().unwrap(), true).unwrap();
    set_owner_only_dacl(secret_file.to_str().unwrap(), false).unwrap();
    assert_eq!(
        std::fs::metadata(&secret_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&secret_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );

    if cfg!(any(target_os = "linux", target_os = "macos")) {
        let mut cfg_fs = test_base_cfg("fs_escape_check");
        cfg_fs.isolation = IsolationLevel::L1;
        cfg_fs.rw_paths = vec![work_dir.to_string_lossy().into_owned()];
        cfg_fs.env_pairs.push((
            "WARDLINE_DENIED_FILE".into(),
            secret_file.to_string_lossy().into_owned(),
        ));
        cfg_fs.env_pairs.push((
            "WARDLINE_ALLOWED_DIR".into(),
            work_dir.to_string_lossy().into_owned(),
        ));
        let out_fs = spawn_isolated(&cfg_fs);
        let stdout_fs = String::from_utf8_lossy(&out_fs.stdout);
        assert_eq!(out_fs.status, EngineStatus::Ok, "fs test: {out_fs:?}");
        assert_eq!(
            out_fs.exit_code,
            0,
            "stdout={stdout_fs} stderr={}",
            String::from_utf8_lossy(&out_fs.stderr)
        );
        assert!(stdout_fs.contains("fs_isolated=1"), "{stdout_fs}");
        assert_eq!(std::fs::read(work_dir.join("ok.txt")).unwrap(), b"hello-ac");
        println!("[PASS] POSIX L1 filesystem isolation: {}", stdout_fs.trim());
    }
    let _ = std::fs::remove_dir_all(&sandbox_root);

    let mut cfg_to = test_base_cfg("sleep_hang");
    cfg_to.isolation = IsolationLevel::L0;
    cfg_to.timeout_ms = 300;
    let out_to = spawn_isolated(&cfg_to);
    assert!(out_to.timed_out, "expected timeout kill, got {out_to:?}");
    assert_eq!(out_to.status, EngineStatus::TimeoutKilled);
    println!("[PASS] POSIX process-group timeout reaper killed hanging child cleanly");

    let mut cfg_oom = test_base_cfg("alloc_oom");
    cfg_oom.isolation = IsolationLevel::L0;
    cfg_oom.max_memory_bytes = 32 * 1024 * 1024;
    let out_oom = spawn_isolated(&cfg_oom);
    assert!(
        out_oom.oom_killed || out_oom.exit_code != 0,
        "expected OOM / non-zero exit under 32 MiB rlimit cap, got {out_oom:?}"
    );
    println!(
        "[PASS] POSIX memory rlimit cap enforced: oom_killed={} exit={} peak={} bytes",
        out_oom.oom_killed, out_oom.exit_code, out_oom.peak_memory_bytes
    );

    harden_current_process_dacl().expect("harden_current_process_dacl succeeds");
    println!("[PASS] POSIX owner-only modes (0600/0700) & dumpable=0 hardened");

    let sys_exe = ["/usr/bin/id", "/bin/echo", "/usr/bin/uname"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
        .expect("standard Unix system binary exists");
    let cfg_sys = SpawnConfig {
        executable: sys_exe.into(),
        cmdline: sys_exe.into(),
        working_dir: "/tmp".into(),
        env_pairs: vec![("PATH".into(), "/usr/bin:/bin".into())],
        isolation: IsolationLevel::L1,
        timeout_ms: 5_000,
        max_memory_bytes: 128 * 1024 * 1024,
        max_processes: 8,
        cpu_rate_percent: 80,
        ..Default::default()
    };
    let out_sys = spawn_isolated(&cfg_sys);
    let stdout_sys = String::from_utf8_lossy(&out_sys.stdout);
    assert_eq!(out_sys.status, EngineStatus::Ok, "sys test: {out_sys:?}");
    assert_eq!(
        out_sys.exit_code,
        0,
        "stdout={stdout_sys} stderr={}",
        String::from_utf8_lossy(&out_sys.stderr)
    );
    assert!(!stdout_sys.trim().is_empty(), "{stdout_sys}");
    println!(
        "[PASS] POSIX L1 system binary ({sys_exe}) exit=0 output={}",
        stdout_sys.trim()
    );
}

fn main() {
    if let Ok(mode) = std::env::var("WARDLINE_PROBE_MODE") {
        std::process::exit(run_child_probe(&mode));
    }

    #[cfg(windows)]
    run_windows_suite();
    #[cfg(unix)]
    run_unix_suite();
}
