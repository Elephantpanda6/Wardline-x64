#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{ArchExecutionMode, CoreError, TargetArch};

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
pub const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xA641;

const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeClass {
    Amd64,
    Arm64,
    Arm64Ec,
    I386,
    UnknownMachine(u16),
    NotPe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeInfo {
    pub class: PeClass,
    pub is_pe32_plus: bool,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub has_aslr: bool,
    pub has_high_entropy_va: bool,
    pub has_dep_nx: bool,
    pub has_cfg: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchValidation {
    pub allowed: bool,
    pub requires_prism_emulation: bool,
    pub suppress_acg_for_emulation: bool,
    pub reason: String,
}

fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    let slice = buf.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    let slice = buf.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn inspect_pe_bytes(bytes: &[u8]) -> PeInfo {
    let non_pe = PeInfo {
        class: PeClass::NotPe,
        is_pe32_plus: false,
        subsystem: 0,
        dll_characteristics: 0,
        has_aslr: false,
        has_high_entropy_va: false,
        has_dep_nx: false,
        has_cfg: false,
    };

    if bytes.len() < 64 || bytes[0] != b'M' || bytes[1] != b'Z' {
        return non_pe;
    }
    let Some(pe_offset_u32) = read_u32_le(bytes, 0x3C) else {
        return non_pe;
    };
    let pe_offset = pe_offset_u32 as usize;
    if bytes.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        return non_pe;
    }
    let Some(machine) = read_u16_le(bytes, pe_offset + 4) else {
        return non_pe;
    };
    let class = match machine {
        IMAGE_FILE_MACHINE_AMD64 => PeClass::Amd64,
        IMAGE_FILE_MACHINE_ARM64 => PeClass::Arm64,
        IMAGE_FILE_MACHINE_ARM64EC => PeClass::Arm64Ec,
        IMAGE_FILE_MACHINE_I386 => PeClass::I386,
        other => PeClass::UnknownMachine(other),
    };

    let opt_offset = pe_offset + 24;
    let opt_magic = read_u16_le(bytes, opt_offset).unwrap_or(0);
    let is_pe32_plus = opt_magic == 0x020B;
    let (subsystem, dll_chars) = if opt_magic == 0x020B || opt_magic == 0x010B {
        (
            read_u16_le(bytes, opt_offset + 68).unwrap_or(0),
            read_u16_le(bytes, opt_offset + 70).unwrap_or(0),
        )
    } else {
        (0, 0)
    };

    PeInfo {
        class,
        is_pe32_plus,
        subsystem,
        dll_characteristics: dll_chars,
        has_aslr: (dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0,
        has_high_entropy_va: (dll_chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0,
        has_dep_nx: (dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0,
        has_cfg: (dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0,
    }
}

pub fn inspect_pe_file(path: &Path) -> Result<PeInfo, CoreError> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 4096];
    let n = file.read(&mut buf)?;
    Ok(inspect_pe_bytes(&buf[..n]))
}

pub fn validate_architecture_policy(
    pe_class: PeClass,
    host_arch: TargetArch,
    mode: ArchExecutionMode,
) -> ArchValidation {
    match (host_arch, mode, pe_class) {
        (TargetArch::X64, _, PeClass::Amd64) => ArchValidation {
            allowed: true,
            requires_prism_emulation: false,
            suppress_acg_for_emulation: false,
            reason: "native AMD64 PE allowed on win-x64".to_string(),
        },
        (TargetArch::X64, _, other) => ArchValidation {
            allowed: false,
            requires_prism_emulation: false,
            suppress_acg_for_emulation: false,
            reason: format!("image class {other:?} rejected by win-x64 native policy"),
        },
        (TargetArch::Arm64, _, PeClass::Arm64) => ArchValidation {
            allowed: true,
            requires_prism_emulation: false,
            suppress_acg_for_emulation: false,
            reason: "native ARM64 PE allowed on win-arm64".to_string(),
        },
        (
            TargetArch::Arm64,
            ArchExecutionMode::AllowArm64Ec | ArchExecutionMode::AllowPrismX64,
            PeClass::Arm64Ec,
        ) => ArchValidation {
            allowed: true,
            requires_prism_emulation: false,
            suppress_acg_for_emulation: false,
            reason: "ARM64EC PE permitted by win-arm64 policy".to_string(),
        },
        (TargetArch::Arm64, ArchExecutionMode::StrictNative, PeClass::Arm64Ec) => ArchValidation {
            allowed: false,
            requires_prism_emulation: false,
            suppress_acg_for_emulation: false,
            reason: "ARM64EC image requires mode = \"allow_arm64ec\"".to_string(),
        },
        (TargetArch::Arm64, ArchExecutionMode::AllowPrismX64, PeClass::Amd64) => ArchValidation {
            allowed: true,
            requires_prism_emulation: true,
            suppress_acg_for_emulation: true,
            reason: "AMD64 PE permitted under ARM64 Prism emulation (ACG suppressed)".to_string(),
        },
        (TargetArch::Arm64, _, PeClass::Amd64) => ArchValidation {
            allowed: false,
            requires_prism_emulation: true,
            suppress_acg_for_emulation: true,
            reason: "Prism x64 emulation blocked by default on win-arm64 (set mode = \"allow_prism_x64\" to permit)".to_string(),
        },
        (TargetArch::Arm64, _, other) => ArchValidation {
            allowed: false,
            requires_prism_emulation: false,
            suppress_acg_for_emulation: false,
            reason: format!("image class {other:?} rejected on win-arm64"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_pe(machine: u16, dll_chars: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");
        buf[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        let opt = 0x80 + 24;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        buf[opt + 70..opt + 72].copy_from_slice(&dll_chars.to_le_bytes());
        buf
    }

    #[test]
    fn parses_pe32_plus_machine_and_mitigations() {
        let flags = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            | IMAGE_DLLCHARACTERISTICS_GUARD_CF
            | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
        let bytes = synthetic_pe(IMAGE_FILE_MACHINE_ARM64, flags);
        let info = inspect_pe_bytes(&bytes);
        assert_eq!(info.class, PeClass::Arm64);
        assert!(info.is_pe32_plus);
        assert!(info.has_aslr);
        assert!(info.has_dep_nx);
        assert!(info.has_cfg);
        assert!(info.has_high_entropy_va);
    }

    #[test]
    fn arm64_prism_default_deny_and_opt_in_toggles_acg() {
        let deny = validate_architecture_policy(
            PeClass::Amd64,
            TargetArch::Arm64,
            ArchExecutionMode::StrictNative,
        );
        assert!(!deny.allowed);
        assert!(deny.requires_prism_emulation);

        let allow = validate_architecture_policy(
            PeClass::Amd64,
            TargetArch::Arm64,
            ArchExecutionMode::AllowPrismX64,
        );
        assert!(allow.allowed);
        assert!(allow.requires_prism_emulation);
        assert!(allow.suppress_acg_for_emulation);
    }

    #[test]
    fn rejects_non_pe_scripts() {
        let info = inspect_pe_bytes(b"@echo off\nwhoami\n");
        assert_eq!(info.class, PeClass::NotPe);
    }
}
