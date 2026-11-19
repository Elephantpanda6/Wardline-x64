#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::TargetArch;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetOs {
    Windows,
    Linux,
    MacOs,
    FreeBsd,
    Other,
}

impl TargetOs {
    pub const fn host() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::MacOs
        }
        #[cfg(target_os = "freebsd")]
        {
            Self::FreeBsd
        }
        #[cfg(not(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd"
        )))]
        {
            Self::Other
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::FreeBsd => "freebsd",
            Self::Other => "other",
        }
    }

    pub const fn is_unix(self) -> bool {
        !matches!(self, Self::Windows)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Laptop,
    Desktop,
    Server,
    SingleBoard,
    Container,
    VirtualMachine,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiliconFamily {
    QualcommSnapdragonOryon,
    AppleSilicon,
    AwsGraviton,
    AmpereAltraOne,
    ArmNeoverse,
    ArmCortexSbc,
    GenericArm64,
    IntelX64,
    AmdX64,
    GenericX64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPlatformProfile {
    pub os: TargetOs,
    pub arch: TargetArch,
    pub distro_tag: String,
    pub device_class: DeviceClass,
    pub silicon_family: SiliconFamily,
    pub logical_cpus: usize,
    pub page_size_bytes: u32,
    pub emulation_layer: String,
    pub l1_mechanism: String,
    pub l2_hypervisor: String,
    pub recommended_usecases: Vec<String>,
}

fn read_trimmed(path: &str) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn detect_linux_device_and_silicon(arch: TargetArch) -> (DeviceClass, SiliconFamily) {
    let in_container = std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
        || read_trimmed("/proc/1/cgroup")
            .map(|c| {
                let lc = c.to_ascii_lowercase();
                lc.contains("docker")
                    || lc.contains("kubepods")
                    || lc.contains("containerd")
                    || lc.contains("lxc")
            })
            .unwrap_or(false);

    let dt_model = read_trimmed("/proc/device-tree/model")
        .or_else(|| read_trimmed("/sys/firmware/devicetree/base/model"))
        .unwrap_or_default();
    let dt_lc = dt_model.to_ascii_lowercase();

    let vendor = read_trimmed("/sys/class/dmi/id/sys_vendor").unwrap_or_default();
    let product = read_trimmed("/sys/class/dmi/id/product_name").unwrap_or_default();
    let chassis = read_trimmed("/sys/class/dmi/id/chassis_type").unwrap_or_default();
    let cpuinfo = read_trimmed("/proc/cpuinfo").unwrap_or_default();
    let cpu_lc = cpuinfo.to_ascii_lowercase();
    let dmi_lc = format!("{vendor} {product}").to_ascii_lowercase();

    let silicon = match arch {
        TargetArch::Arm64 => {
            if dmi_lc.contains("graviton")
                || (dmi_lc.contains("amazon ec2") && cpu_lc.contains("0xd40"))
                || (dmi_lc.contains("amazon ec2") && cpu_lc.contains("0xd0c"))
            {
                SiliconFamily::AwsGraviton
            } else if dmi_lc.contains("ampere") || dmi_lc.contains("altra") {
                SiliconFamily::AmpereAltraOne
            } else if dt_lc.contains("apple") || dmi_lc.contains("apple") {
                SiliconFamily::AppleSilicon
            } else if dt_lc.contains("qualcomm")
                || dt_lc.contains("snapdragon")
                || dt_lc.contains("x1e")
                || dt_lc.contains("oryon")
            {
                SiliconFamily::QualcommSnapdragonOryon
            } else if cpu_lc.contains("0xd0c")
                || cpu_lc.contains("0xd40")
                || cpu_lc.contains("0xd49")
                || cpu_lc.contains("0xd4f")
                || dmi_lc.contains("neoverse")
            {
                SiliconFamily::ArmNeoverse
            } else if dt_lc.contains("raspberry")
                || dt_lc.contains("jetson")
                || dt_lc.contains("orange pi")
                || dt_lc.contains("rockchip")
                || dt_lc.contains("beagle")
                || dt_lc.contains("odroid")
            {
                SiliconFamily::ArmCortexSbc
            } else {
                SiliconFamily::GenericArm64
            }
        }
        TargetArch::X64 => {
            if cpu_lc.contains("authenticamd") {
                SiliconFamily::AmdX64
            } else if cpu_lc.contains("genuineintel") {
                SiliconFamily::IntelX64
            } else {
                SiliconFamily::GenericX64
            }
        }
    };

    let device_class = if in_container {
        DeviceClass::Container
    } else if matches!(silicon, SiliconFamily::ArmCortexSbc) {
        DeviceClass::SingleBoard
    } else if matches!(
        silicon,
        SiliconFamily::AwsGraviton | SiliconFamily::AmpereAltraOne | SiliconFamily::ArmNeoverse
    ) {
        DeviceClass::Server
    } else if matches!(
        chassis.as_str(),
        "8" | "9" | "10" | "14" | "31" | "32"
    ) {
        DeviceClass::Laptop
    } else if matches!(
        chassis.as_str(),
        "17" | "23" | "25" | "28" | "29"
    ) || dmi_lc.contains("amazon ec2")
        || dmi_lc.contains("google compute")
        || dmi_lc.contains("oraclecloud")
    {
        DeviceClass::Server
    } else if dmi_lc.contains("qemu")
        || dmi_lc.contains("vmware")
        || dmi_lc.contains("virtualbox")
        || dmi_lc.contains("virtual machine")
        || dmi_lc.contains("bochs")
        || cpu_lc.contains("hypervisor")
    {
        DeviceClass::VirtualMachine
    } else if matches!(
        chassis.as_str(),
        "3" | "4" | "5" | "6" | "7" | "13" | "15" | "16" | "24"
    ) {
        DeviceClass::Desktop
    } else if matches!(silicon, SiliconFamily::QualcommSnapdragonOryon) {
        DeviceClass::Laptop
    } else {
        DeviceClass::Unknown
    };

    (device_class, silicon)
}

fn detect_windows_device_and_silicon(arch: TargetArch) -> (DeviceClass, SiliconFamily) {
    let proc_id = std::env::var("PROCESSOR_IDENTIFIER")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let computer = std::env::var("COMPUTERNAME")
        .unwrap_or_default()
        .to_ascii_lowercase();

    let silicon = match arch {
        TargetArch::Arm64 => {
            if proc_id.contains("qualcomm")
                || proc_id.contains("snapdragon")
                || proc_id.contains("oryon")
                || proc_id.contains("qcom")
            {
                SiliconFamily::QualcommSnapdragonOryon
            } else if proc_id.contains("ampere") {
                SiliconFamily::AmpereAltraOne
            } else if proc_id.contains("neoverse") {
                SiliconFamily::ArmNeoverse
            } else {
                SiliconFamily::GenericArm64
            }
        }
        TargetArch::X64 => {
            if proc_id.contains("amd") {
                SiliconFamily::AmdX64
            } else if proc_id.contains("intel") {
                SiliconFamily::IntelX64
            } else {
                SiliconFamily::GenericX64
            }
        }
    };

    let device_class = if computer.contains("laptop")
        || computer.contains("notebook")
        || computer.contains("surface")
        || computer.contains("thinkpad")
        || matches!(silicon, SiliconFamily::QualcommSnapdragonOryon)
    {
        DeviceClass::Laptop
    } else if matches!(
        silicon,
        SiliconFamily::AmpereAltraOne | SiliconFamily::ArmNeoverse | SiliconFamily::AwsGraviton
    ) || computer.contains("server")
    {
        DeviceClass::Server
    } else if computer.contains("desktop") || computer.contains("workstation") {
        DeviceClass::Desktop
    } else {
        DeviceClass::Unknown
    };

    (device_class, silicon)
}

fn default_usecases(os: TargetOs, arch: TargetArch, device_class: DeviceClass) -> Vec<String> {
    let mut out = vec![
        "Local IDE / MCP AI coding agent tool containment".to_string(),
        "Zero-secret credential brokering & SSRF-pinned HTTPS egress".to_string(),
        "Multi-agent cryptographic capability delegation (Ed25519 WardCert)".to_string(),
    ];
    match (arch, device_class) {
        (TargetArch::Arm64, DeviceClass::Laptop | DeviceClass::Desktop) => {
            out.push("ARM64 workstation native build/test gating with emulation firewall".to_string());
        }
        (TargetArch::Arm64, DeviceClass::Server) => {
            out.push("Cloud ARM64 autonomous ops & CI/CD runner isolation".to_string());
        }
        (TargetArch::Arm64, DeviceClass::SingleBoard) => {
            out.push("Edge ARM64 appliance / robotics zero-trust tool runner".to_string());
        }
        (_, DeviceClass::Server | DeviceClass::Container) => {
            out.push("Autonomous cloud/CI build & remediation agent containment".to_string());
        }
        _ => {
            out.push(format!(
                "Cross-OS {} ({:?}) deterministic agent execution boundary",
                os.as_str(),
                arch
            ));
        }
    }
    out
}

pub fn detect_host_platform_profile(
    page_size_bytes: u32,
    is_emulated: bool,
) -> HostPlatformProfile {
    let os = TargetOs::host();
    let arch = TargetArch::host();
    let logical_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let (device_class, silicon_family) = match os {
        TargetOs::Windows => detect_windows_device_and_silicon(arch),
        TargetOs::Linux => detect_linux_device_and_silicon(arch),
        TargetOs::MacOs => {
            let silicon = match arch {
                TargetArch::Arm64 => SiliconFamily::AppleSilicon,
                TargetArch::X64 => SiliconFamily::IntelX64,
            };
            (DeviceClass::Laptop, silicon)
        }
        TargetOs::FreeBsd | TargetOs::Other => {
            let silicon = match arch {
                TargetArch::Arm64 => SiliconFamily::GenericArm64,
                TargetArch::X64 => SiliconFamily::GenericX64,
            };
            (DeviceClass::Server, silicon)
        }
    };

    let emulation_layer = if is_emulated {
        match os {
            TargetOs::Windows => "Windows Prism".to_string(),
            TargetOs::MacOs => "Apple Rosetta 2".to_string(),
            TargetOs::Linux | TargetOs::FreeBsd | TargetOs::Other => {
                "Linux binfmt/QEMU/FEX".to_string()
            }
        }
    } else {
        "None".to_string()
    };

    let l1_mechanism = match os {
        TargetOs::Windows => "Win32 AppContainer + JobObject".to_string(),
        TargetOs::Linux => "Linux UserNS + Landlock + Seccomp".to_string(),
        TargetOs::MacOs => "macOS Seatbelt (SBPL)".to_string(),
        TargetOs::FreeBsd => "FreeBSD Capsicum + Rlimit".to_string(),
        TargetOs::Other => "POSIX Rlimit + FD Containment".to_string(),
    };

    let l2_hypervisor = match os {
        TargetOs::Windows => "Hyper-V HCS / WHPX".to_string(),
        TargetOs::Linux => "Linux KVM".to_string(),
        TargetOs::MacOs => "Apple Virtualization.framework".to_string(),
        TargetOs::FreeBsd => "FreeBSD bhyve".to_string(),
        TargetOs::Other => "None".to_string(),
    };

    HostPlatformProfile {
        os,
        arch,
        distro_tag: arch.distro_tag().to_string(),
        device_class,
        silicon_family,
        logical_cpus,
        page_size_bytes,
        emulation_layer,
        l1_mechanism,
        l2_hypervisor,
        recommended_usecases: default_usecases(os, arch, device_class),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_profile_populates_consistent_os_and_arch() {
        let profile = detect_host_platform_profile(4096, false);
        assert_eq!(profile.os, TargetOs::host());
        assert_eq!(profile.arch, TargetArch::host());
        assert_eq!(profile.distro_tag, TargetArch::host().distro_tag());
        assert!(profile.logical_cpus >= 1);
        assert_eq!(profile.emulation_layer, "None");
        assert!(!profile.l1_mechanism.is_empty());
        assert!(!profile.recommended_usecases.is_empty());

        let emulated = detect_host_platform_profile(16384, true);
        assert_ne!(emulated.emulation_layer, "None");
    }
}
