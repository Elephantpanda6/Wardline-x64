#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

const BLOCKED_LOLBINS: &[&str] = &[
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

const BLOCKED_SCRIPT_EXTENSIONS: &[&str] = &[
    "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sct",
    "lnk", "com", "scr", "pif", "msi", "cpl",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableRisk {
    Clean,
    LolBin(String),
    ScriptExtension(String),
}

fn clean_windows_filename(raw: &str) -> String {
    let base = raw
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(raw)
        .trim_end_matches(['.', ' '])
        .to_ascii_lowercase();
    base
}

pub fn classify_executable_name(executable: &str) -> ExecutableRisk {
    let clean = clean_windows_filename(executable);
    if clean.is_empty() {
        return ExecutableRisk::Clean;
    }
    if BLOCKED_LOLBINS.contains(&clean.as_str()) {
        return ExecutableRisk::LolBin(clean);
    }
    if let Some((_, ext)) = clean.rsplit_once('.') {
        if BLOCKED_SCRIPT_EXTENSIONS.contains(&ext) {
            return ExecutableRisk::ScriptExtension(ext.to_string());
        }
    }
    ExecutableRisk::Clean
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
}
