use std::path::Path;

const MAX_WRAPPER_UNWRAP_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrappedCommand {
    pub executable: String,
    pub args: Vec<String>,
    pub wrapper_chain: Vec<String>,
}

pub fn normalize_bin_stem(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let lower = base.trim().to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat", ".com"] {
        if let Some(stripped) = lower.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    lower
}

/// Version-tolerant basename matcher (e.g. `python3.12` or `python3` matches `python`),
/// rejecting unrelated prefix collisions (e.g. `pythonista` or `shred`).
pub fn bin_matches(candidate: &str, canonical: &str) -> bool {
    let cand = normalize_bin_stem(candidate);
    let canon = normalize_bin_stem(canonical);
    if cand.is_empty() || canon.is_empty() {
        return false;
    }
    if cand == canon {
        return true;
    }
    if let Some(rest) = cand.strip_prefix(&canon) {
        if let Some(first) = rest.chars().next() {
            if first.is_ascii_digit() {
                return rest
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == '-');
            }
            if (first == '-' || first == '.') && rest.len() > 1 {
                let tail = &rest[1..];
                return tail
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit());
            }
        }
    }
    false
}

fn is_env_assignment(tok: &str) -> bool {
    !tok.starts_with('-') && tok.contains('=') && !tok.starts_with('=')
}

/// Recursively unwraps common wrapper commands (`env`, `timeout`, `nice`, `nohup`, `stdbuf`,
/// `sudo`, `doas`, `busybox`) up to `MAX_WRAPPER_UNWRAP_DEPTH`.
pub fn unwrap_command(executable: &str, args: &[String]) -> Result<UnwrappedCommand, String> {
    let mut cur_exe = executable.to_string();
    let mut cur_args: Vec<String> = args.to_vec();
    let mut chain = Vec::new();

    for _ in 0..MAX_WRAPPER_UNWRAP_DEPTH {
        let stem = normalize_bin_stem(&cur_exe);
        if stem == "env" {
            let mut i = 0usize;
            let mut next_cmd: Option<usize> = None;
            while i < cur_args.len() {
                let a = &cur_args[i];
                let al = a.as_str();
                if al == "--" {
                    if i + 1 < cur_args.len() {
                        next_cmd = Some(i + 1);
                    }
                    break;
                }
                if al == "-S"
                    || al == "--split-string"
                    || al.starts_with("--split-string=")
                    || (al.starts_with('-') && !al.starts_with("--") && al[1..].contains('S'))
                {
                    return Err(
                        "wrapper 'env' with split-string (-S/--split-string) is blocked by argv shield"
                            .into(),
                    );
                }
                if al == "-u" || al == "--unset" || al == "-C" || al == "--chdir" {
                    i += 2;
                    continue;
                }
                if al.starts_with('-') || is_env_assignment(al) {
                    i += 1;
                    continue;
                }
                next_cmd = Some(i);
                break;
            }
            let Some(idx) = next_cmd else {
                break;
            };
            chain.push(stem);
            cur_exe = cur_args[idx].clone();
            cur_args = cur_args[idx + 1..].to_vec();
            continue;
        }

        if stem == "timeout" {
            let mut i = 0usize;
            while i < cur_args.len() {
                let a = &cur_args[i];
                if a == "-s" || a == "--signal" || a == "-k" || a == "--kill-after" {
                    i += 2;
                } else if a.starts_with('-') {
                    i += 1;
                } else {
                    break;
                }
            }
            // Skip duration token (e.g., "10", "5s") before target command.
            if i + 1 < cur_args.len() {
                chain.push(stem);
                cur_exe = cur_args[i + 1].clone();
                cur_args = cur_args[i + 2..].to_vec();
                continue;
            }
            break;
        }

        if stem == "nice" {
            let mut i = 0usize;
            while i < cur_args.len() {
                let a = &cur_args[i];
                if a == "-n" || a == "--adjustment" {
                    i += 2;
                } else if a.starts_with('-') {
                    i += 1;
                } else {
                    break;
                }
            }
            if i < cur_args.len() {
                chain.push(stem);
                cur_exe = cur_args[i].clone();
                cur_args = cur_args[i + 1..].to_vec();
                continue;
            }
            break;
        }

        if stem == "nohup" {
            let mut i = 0usize;
            while i < cur_args.len() && cur_args[i] == "--" {
                i += 1;
            }
            if i < cur_args.len() {
                chain.push(stem);
                cur_exe = cur_args[i].clone();
                cur_args = cur_args[i + 1..].to_vec();
                continue;
            }
            break;
        }

        if stem == "stdbuf" {
            let mut i = 0usize;
            while i < cur_args.len() {
                let a = &cur_args[i];
                if a == "-i" || a == "-o" || a == "-e" {
                    i += 2;
                } else if a.starts_with('-') {
                    i += 1;
                } else {
                    break;
                }
            }
            if i < cur_args.len() {
                chain.push(stem);
                cur_exe = cur_args[i].clone();
                cur_args = cur_args[i + 1..].to_vec();
                continue;
            }
            break;
        }

        if stem == "sudo" || stem == "doas" {
            let mut i = 0usize;
            while i < cur_args.len() {
                let a = &cur_args[i];
                if a == "-s" || a == "--shell" || a == "-i" || a == "--login" {
                    return Err(format!("privilege wrapper '{stem}' interactive/shell flag '{a}' blocked"));
                }
                if a == "-u" || a == "-g" || a == "-C" || a == "-p" || a == "-r" || a == "-t" || a == "-U" {
                    i += 2;
                } else if a.starts_with('-') {
                    i += 1;
                } else {
                    break;
                }
            }
            if i < cur_args.len() {
                chain.push(stem);
                cur_exe = cur_args[i].clone();
                cur_args = cur_args[i + 1..].to_vec();
                continue;
            }
            break;
        }

        if stem == "busybox" && !cur_args.is_empty() && !cur_args[0].starts_with('-') {
            chain.push(stem);
            cur_exe = cur_args[0].clone();
            cur_args = cur_args[1..].to_vec();
            continue;
        }

        break;
    }

    Ok(UnwrappedCommand {
        executable: cur_exe,
        args: cur_args,
        wrapper_chain: chain,
    })
}

fn is_shell_binary(exe: &str) -> bool {
    const SHELLS: &[&str] = &[
        "sh", "bash", "dash", "zsh", "ksh", "fish", "ash", "csh", "tcsh", "cmd", "powershell",
        "pwsh",
    ];
    SHELLS.iter().any(|s| bin_matches(exe, s))
}

fn is_interpreter_binary(exe: &str) -> bool {
    const INTERPS: &[&str] = &[
        "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "lua", "luajit", "php",
        "bun", "deno",
    ];
    INTERPS.iter().any(|s| bin_matches(exe, s))
}

/// Inspects an unwrapped command and argv for inline code execution, shell flags, and AWK escapes.
/// Returns `Err((reason, remediation))` on violation.
pub fn inspect_argv(
    cmd: &UnwrappedCommand,
    allow_inline_shell: bool,
) -> Result<(), (String, String)> {
    let exe = cmd.executable.as_str();
    let stem = normalize_bin_stem(exe);

    if matches!(stem.as_str(), "awk" | "gawk" | "nawk" | "mawk") {
        return Err((
            format!("'{stem}' blocked outright: inline AWK programs can invoke system() shell escapes"),
            "Replace inline awk text processing with an allowlisted fixed binary or host file broker read.".into(),
        ));
    }

    if is_shell_binary(exe) && !allow_inline_shell {
        for arg in &cmd.args {
            if arg == "--" {
                break;
            }
            let al = arg.to_ascii_lowercase();
            let short_cluster = al.starts_with('-') && !al.starts_with("--") && al.len() > 1;
            let short_has_bad = short_cluster
                && al[1..]
                    .chars()
                    .any(|ch| matches!(ch, 'c' | 'i' | 's' | 'l'));
            if matches!(
                al.as_str(),
                "-c" | "/c" | "/k" | "-command" | "-encodedcommand" | "-enc" | "--rcfile"
                    | "--init-file" | "--login" | "-i"
            ) || al.starts_with("--rcfile=")
                || al.starts_with("--init-file=")
                || al.starts_with("-c=")
                || short_has_bad
            {
                return Err((
                    format!("shell '{stem}' inline/startup/interactive flag '{arg}' blocked by argv shield"),
                    "Set [execution].allow_inline_shell = true only if inline shell evaluation is strictly intended.".into(),
                ));
            }
        }
    }

    if is_interpreter_binary(exe) {
        let is_python = bin_matches(exe, "python") || bin_matches(exe, "python3") || bin_matches(exe, "python2");
        let is_deno_or_bun = bin_matches(exe, "deno") || bin_matches(exe, "bun");
        for (idx, arg) in cmd.args.iter().enumerate() {
            if arg == "--" {
                break;
            }
            if idx == 0 && is_deno_or_bun && arg.eq_ignore_ascii_case("eval") {
                return Err((
                    format!("interpreter '{stem} eval' blocked by argv shield"),
                    "Run a reviewed script file from workspace_read instead of inline eval.".into(),
                ));
            }
            let al = arg.to_ascii_lowercase();
            if matches!(
                al.as_str(),
                "-c" | "-e" | "-p" | "-r" | "-x" | "-i" | "--eval" | "--interactive" | "--print"
            ) || al == "-e" // uppercase handled via exact match below
                || al.starts_with("-c=")
                || al.starts_with("-e=")
                || al.starts_with("--eval=")
                || al.starts_with("--input-type=")
                || (is_python && (al == "-m" || al.starts_with("-m=")))
            {
                return Err((
                    format!("interpreter '{stem}' inline-execution flag '{arg}' blocked by argv shield"),
                    "Invoke an audited script path instead of inline code execution or Python -m CWD imports.".into(),
                ));
            }
            if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
                for ch in arg[1..].chars() {
                    let bad = matches!(ch, 'c' | 'e' | 'E' | 'p' | 'r' | 'R' | 'x' | 'i')
                        || (is_python && ch == 'm');
                    if bad {
                        return Err((
                            format!("interpreter '{stem}' bundled inline-code flag cluster '{arg}' (contains '-{ch}') blocked by argv shield"),
                            "Invoke an audited script path instead of inline interpreter flags.".into(),
                        ));
                    }
                }
            }
        }
    }

    let _ = Path::new(exe);
    Ok(())
}

/// Validates HTTP method per RFC 9110 `token` (`1*tchar`).
pub fn method_is_token(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'
                        | b'_' | b'`' | b'|' | b'~'
                )
        })
}

/// Validates an HTTP origin-form request target is free of CRLF, whitespace, NULs, userinfo tricks,
/// or directory traversal segments.
pub fn request_target_is_clean(target: &str) -> bool {
    if target.is_empty() || (!target.starts_with('/') && !target.starts_with('?')) {
        return false;
    }
    if target
        .bytes()
        .any(|b| b <= 0x20 || b == 0x7F || b == b'#')
    {
        return false;
    }
    let lower = target.to_ascii_lowercase();
    if lower.contains("%2e%2e") || lower.contains("%0d") || lower.contains("%0a") {
        return false;
    }
    let path_part = target.split('?').next().unwrap_or(target);
    !path_part.split('/').any(|seg| seg == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_matches_version_tolerant_without_prefix_confusion() {
        assert!(bin_matches("/usr/bin/python3.12", "python"));
        assert!(bin_matches("python3", "python"));
        assert!(bin_matches(r"C:\Python312\python.exe", "python"));
        assert!(!bin_matches("pythonista", "python"));
        assert!(!bin_matches("shred", "sh"));
        assert!(!bin_matches("sha256sum", "sh"));
    }

    #[test]
    fn unwraps_nested_wrappers_and_blocks_env_split_string() {
        let u = unwrap_command(
            "/usr/bin/env",
            &[
                "FOO=bar".into(),
                "timeout".into(),
                "10s".into(),
                "nice".into(),
                "-n".into(),
                "5".into(),
                "busybox".into(),
                "sh".into(),
                "-c".into(),
                "id".into(),
            ],
        )
        .unwrap();
        assert_eq!(u.executable, "sh");
        assert_eq!(u.wrapper_chain, vec!["env", "timeout", "nice", "busybox"]);
        assert!(inspect_argv(&u, false).is_err());

        let env_split = unwrap_command("env", &["-S".into(), "python3 -c 'print(1)'".into()]);
        assert!(env_split.is_err());
    }

    #[test]
    fn detects_bundled_interpreter_flags_and_awk_and_rfc9110() {
        let py_bundled = UnwrappedCommand {
            executable: "python3.11".into(),
            args: vec!["-uc".into(), "import os".into()],
            wrapper_chain: vec![],
        };
        assert!(inspect_argv(&py_bundled, false).is_err());

        let py_mod = UnwrappedCommand {
            executable: "python3".into(),
            args: vec!["-m".into(), "http.server".into()],
            wrapper_chain: vec![],
        };
        assert!(inspect_argv(&py_mod, false).is_err());

        let awk = UnwrappedCommand {
            executable: "/usr/bin/gawk".into(),
            args: vec!["{print}".into()],
            wrapper_chain: vec![],
        };
        assert!(inspect_argv(&awk, true).is_err());

        assert!(method_is_token("GET"));
        assert!(!method_is_token("GET HTTP/1.1"));
        assert!(request_target_is_clean("/repos/acme/app/issues?state=open"));
        assert!(!request_target_is_clean("/repos/../admin"));
        assert!(!request_target_is_clean("/a\r\nHost: evil"));
    }
}
