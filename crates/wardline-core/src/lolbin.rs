#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::path::looks_like_windows_path;
use crate::TargetOs;

const BLOCKED_WINDOWS_LOLBINS: &[&str] = &[
    "cmd.exe",
    "cmd",
    "powershell.exe",
    "powershell",
    "pwsh.exe",
    "pwsh",
    "wscript.exe",
    "wscript",
    "cscript.exe",
    "cscript",
    "mshta.exe",
    "mshta",
    "rundll32.exe",
    "rundll32",
    "regsvr32.exe",
    "regsvr32",
    "certutil.exe",
    "certutil",
    "bitsadmin.exe",
    "bitsadmin",
    "msiexec.exe",
    "msiexec",
    "wmic.exe",
    "wmic",
    "forfiles.exe",
    "forfiles",
    "pcalua.exe",
    "pcalua",
    "installutil.exe",
    "installutil",
    "msbuild.exe",
    "msbuild",
    "bash.exe",
    "bash",
    "wsl.exe",
    "wsl",
    "reg.exe",
    "reg",
    "schtasks.exe",
    "schtasks",
    "sc.exe",
    "sc",
    "netsh.exe",
    "netsh",
    "odbcconf.exe",
    "odbcconf",
    "mavinject.exe",
    "mavinject",
    "cmstp.exe",
    "cmstp",
];

const BLOCKED_WINDOWS_SCRIPT_EXTENSIONS: &[&str] = &[
    "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sct",
    "lnk", "com", "scr", "pif", "msi", "cpl",
];

const BLOCKED_UNIX_LOLBINS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "osascript",
    "perl",
    "ruby",
    "python",
    "python3",
    "php",
    "lua",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "sudo",
    "su",
    "doas",
    "pkexec",
    "nsenter",
    "unshare",
    "chroot",
    "expect",
    "tclsh",
    "env",
    "xargs",
    "nohup",
    "setsid",
    "script",
];

const BLOCKED_UNIX_SCRIPT_EXTENSIONS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "csh",
    "ksh",
    "fish",
    "command",
    "applescript",
    "scpt",
    "py",
    "rb",
    "pl",
    "php",
    "lua",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableRisk {
    Clean,
    LolBin(String),
    ScriptExtension(String),
}

fn clean_executable_basename(raw: &str) -> String {
    raw.rsplit(['\\', '/'])
        .next()
        .unwrap_or(raw)
        .trim_end_matches(['.', ' '])
        .to_ascii_lowercase()
}

pub fn classify_executable_for_os(executable: &str, os: TargetOs) -> ExecutableRisk {
    let clean = clean_executable_basename(executable);
    if clean.is_empty() {
        return ExecutableRisk::Clean;
    }

    let check_windows = os == TargetOs::Windows
        || looks_like_windows_path(executable)
        || clean.ends_with(".exe");
    if check_windows && BLOCKED_WINDOWS_LOLBINS.contains(&clean.as_str()) {
        return ExecutableRisk::LolBin(clean);
    }

    if os.is_unix() && BLOCKED_UNIX_LOLBINS.contains(&clean.as_str()) {
        return ExecutableRisk::LolBin(clean);
    }

    if let Some((_, ext)) = clean.rsplit_once('.') {
        if (check_windows || BLOCKED_WINDOWS_SCRIPT_EXTENSIONS.contains(&ext))
            && BLOCKED_WINDOWS_SCRIPT_EXTENSIONS.contains(&ext)
        {
            return ExecutableRisk::ScriptExtension(ext.to_string());
        }
        if os.is_unix() && BLOCKED_UNIX_SCRIPT_EXTENSIONS.contains(&ext) {
            return ExecutableRisk::ScriptExtension(ext.to_string());
        }
    }

    ExecutableRisk::Clean
}

pub fn classify_executable_name(executable: &str) -> ExecutableRisk {
    classify_executable_for_os(executable, TargetOs::host())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_lolbins_including_trailing_dot_evasion() {
        assert!(matches!(
            classify_executable_name(r"C:\Windows\System32\cmd.exe. "),
            ExecutableRisk::LolBin(_)
        ));
        assert!(matches!(
            classify_executable_name("PowerShell.EXE"),
            ExecutableRisk::LolBin(_)
        ));
        assert!(matches!(
            classify_executable_name(r"D:\tools\payload.Ps1."),
            ExecutableRisk::ScriptExtension(_)
        ));
        assert_eq!(
            classify_executable_name(r"C:\Tools\rg.exe"),
            ExecutableRisk::Clean
        );
    }

    #[test]
    fn blocks_unix_lolbins_and_scripts() {
        assert!(matches!(
            classify_executable_for_os("/bin/sh", TargetOs::Linux),
            ExecutableRisk::LolBin(_)
        ));
        assert!(matches!(
            classify_executable_for_os("/usr/bin/python3", TargetOs::MacOs),
            ExecutableRisk::LolBin(_)
        ));
        assert!(matches!(
            classify_executable_for_os("helper.py", TargetOs::Linux),
            ExecutableRisk::ScriptExtension(_)
        ));
        assert_eq!(
            classify_executable_for_os("/usr/bin/id", TargetOs::Linux),
            ExecutableRisk::Clean
        );
    }
}
