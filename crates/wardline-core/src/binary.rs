#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::pe::{inspect_pe_bytes, validate_architecture_policy, PeClass};
use crate::{ArchExecutionMode, ArchValidation, CoreError, TargetArch, TargetOs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    MachOUniversal,
    ScriptOrRaw,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryArch {
    X64,
    Arm64,
    Arm64Ec,
    X86,
    Arm32,
    RiscV64,
    Unknown(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub arches: Vec<BinaryArch>,
    pub is_64bit: bool,
    pub has_pie_or_aslr: bool,
    pub has_nx_stack: bool,
    pub has_cfg_or_relro: bool,
    pub has_bti: bool,
    pub has_pac: bool,
    pub has_cet_ibt: bool,
    pub has_cet_shstk: bool,
}

impl BinaryInfo {
    fn script_or_raw() -> Self {
        Self {
            format: BinaryFormat::ScriptOrRaw,
            arches: Vec::new(),
            is_64bit: false,
            has_pie_or_aslr: false,
            has_nx_stack: false,
            has_cfg_or_relro: false,
            has_bti: false,
            has_pac: false,
            has_cet_ibt: false,
            has_cet_shstk: false,
        }
    }

    pub fn to_pe_class(&self) -> PeClass {
        if self.format != BinaryFormat::Pe {
            return PeClass::NotPe;
        }
        match self.arches.first().copied() {
            Some(BinaryArch::X64) => PeClass::Amd64,
            Some(BinaryArch::Arm64) => PeClass::Arm64,
            Some(BinaryArch::Arm64Ec) => PeClass::Arm64Ec,
            Some(BinaryArch::X86) => PeClass::I386,
            Some(BinaryArch::Unknown(code)) => PeClass::UnknownMachine(code as u16),
            _ => PeClass::NotPe,
        }
    }
}

fn read_u16(buf: &[u8], off: usize, le: bool) -> Option<u16> {
    let s = buf.get(off..off.checked_add(2)?)?;
    Some(if le {
        u16::from_le_bytes([s[0], s[1]])
    } else {
        u16::from_be_bytes([s[0], s[1]])
    })
}

fn read_u32(buf: &[u8], off: usize, le: bool) -> Option<u32> {
    let s = buf.get(off..off.checked_add(4)?)?;
    Some(if le {
        u32::from_le_bytes([s[0], s[1], s[2], s[3]])
    } else {
        u32::from_be_bytes([s[0], s[1], s[2], s[3]])
    })
}

fn read_u64(buf: &[u8], off: usize, le: bool) -> Option<u64> {
    let s = buf.get(off..off.checked_add(8)?)?;
    Some(if le {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    } else {
        u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

fn align_up(v: usize, align: usize) -> usize {
    if align <= 1 {
        return v;
    }
    let rem = v % align;
    if rem == 0 {
        v
    } else {
        v.saturating_add(align - rem)
    }
}

fn parse_gnu_property_note(desc: &[u8], le: bool, is_64bit: bool, info: &mut BinaryInfo) {
    let align = if is_64bit { 8 } else { 4 };
    let mut off = 0usize;
    while off.saturating_add(8) <= desc.len() {
        let Some(pr_type) = read_u32(desc, off, le) else {
            break;
        };
        let Some(pr_datasz) = read_u32(desc, off + 4, le).map(|v| v as usize) else {
            break;
        };
        let data_start = off + 8;
        let Some(data_end) = data_start.checked_add(pr_datasz) else {
            break;
        };
        if data_end > desc.len() {
            break;
        }
        if pr_datasz >= 4 {
            if let Some(flags) = read_u32(desc, data_start, le) {
                if pr_type == 0xC000_0000 {
                    // GNU_PROPERTY_AARCH64_FEATURE_1_AND
                    if (flags & 0x1) != 0 {
                        info.has_bti = true;
                    }
                    if (flags & 0x2) != 0 {
                        info.has_pac = true;
                    }
                } else if pr_type == 0xC000_0002 {
                    // GNU_PROPERTY_X86_FEATURE_1_AND
                    if (flags & 0x1) != 0 {
                        info.has_cet_ibt = true;
                    }
                    if (flags & 0x2) != 0 {
                        info.has_cet_shstk = true;
                    }
                }
            }
        }
        off = align_up(data_end, align);
    }
}

fn parse_elf_notes(note_bytes: &[u8], le: bool, is_64bit: bool, info: &mut BinaryInfo) {
    let mut off = 0usize;
    while off.saturating_add(12) <= note_bytes.len() {
        let Some(namesz) = read_u32(note_bytes, off, le).map(|v| v as usize) else {
            break;
        };
        let Some(descsz) = read_u32(note_bytes, off + 4, le).map(|v| v as usize) else {
            break;
        };
        let Some(ntype) = read_u32(note_bytes, off + 8, le) else {
            break;
        };
        let name_off = off + 12;
        let Some(name_end) = name_off.checked_add(namesz) else {
            break;
        };
        if name_end > note_bytes.len() {
            break;
        }
        let desc_off = align_up(name_end, 4);
        let Some(desc_end) = desc_off.checked_add(descsz) else {
            break;
        };
        if desc_end > note_bytes.len() {
            break;
        }
        let name = &note_bytes[name_off..name_end];
        if ntype == 5 && (name == b"GNU\0" || name == b"GNU") {
            parse_gnu_property_note(&note_bytes[desc_off..desc_end], le, is_64bit, info);
        }
        off = align_up(desc_end, 4);
    }
}

fn inspect_elf_bytes(bytes: &[u8]) -> BinaryInfo {
    if bytes.len() < 52 || &bytes[0..4] != b"\x7fELF" {
        return BinaryInfo::script_or_raw();
    }
    let ei_class = bytes[4];
    let ei_data = bytes[5];
    let is_64bit = match ei_class {
        1 => false,
        2 => true,
        _ => return BinaryInfo::script_or_raw(),
    };
    let le = match ei_data {
        1 => true,
        2 => false,
        _ => return BinaryInfo::script_or_raw(),
    };
    if is_64bit && bytes.len() < 64 {
        return BinaryInfo::script_or_raw();
    }

    let e_type = read_u16(bytes, 16, le).unwrap_or(0);
    let e_machine = read_u16(bytes, 18, le).unwrap_or(0);
    let arch = match e_machine {
        183 => BinaryArch::Arm64,
        62 => BinaryArch::X64,
        3 => BinaryArch::X86,
        40 => BinaryArch::Arm32,
        243 if is_64bit => BinaryArch::RiscV64,
        other => BinaryArch::Unknown(u32::from(other)),
    };

    let mut info = BinaryInfo {
        format: BinaryFormat::Elf,
        arches: vec![arch],
        is_64bit,
        has_pie_or_aslr: e_type == 3, // ET_DYN
        has_nx_stack: false,
        has_cfg_or_relro: false,
        has_bti: false,
        has_pac: false,
        has_cet_ibt: false,
        has_cet_shstk: false,
    };

    let (phoff, phentsize, phnum) = if is_64bit {
        (
            read_u64(bytes, 32, le).unwrap_or(0) as usize,
            read_u16(bytes, 54, le).unwrap_or(0) as usize,
            read_u16(bytes, 56, le).unwrap_or(0) as usize,
        )
    } else {
        (
            read_u32(bytes, 28, le).unwrap_or(0) as usize,
            read_u16(bytes, 42, le).unwrap_or(0) as usize,
            read_u16(bytes, 44, le).unwrap_or(0) as usize,
        )
    };

    let min_phent = if is_64bit { 56 } else { 32 };
    if phoff > 0 && phentsize >= min_phent {
        for i in 0..phnum.min(64) {
            let Some(off) = phoff.checked_add(i.saturating_mul(phentsize)) else {
                break;
            };
            if off.saturating_add(min_phent) > bytes.len() {
                break;
            }
            let p_type = read_u32(bytes, off, le).unwrap_or(0);
            let p_flags = if is_64bit {
                read_u32(bytes, off + 4, le).unwrap_or(0)
            } else {
                read_u32(bytes, off + 24, le).unwrap_or(0)
            };
            if p_type == 0x6474_E551 {
                // PT_GNU_STACK
                if (p_flags & 0x1) == 0 {
                    info.has_nx_stack = true;
                }
            } else if p_type == 0x6474_E552 {
                // PT_GNU_RELRO
                info.has_cfg_or_relro = true;
            } else if p_type == 4 {
                // PT_NOTE
                let (p_offset, p_filesz) = if is_64bit {
                    (
                        read_u64(bytes, off + 8, le).unwrap_or(0) as usize,
                        read_u64(bytes, off + 32, le).unwrap_or(0) as usize,
                    )
                } else {
                    (
                        read_u32(bytes, off + 4, le).unwrap_or(0) as usize,
                        read_u32(bytes, off + 16, le).unwrap_or(0) as usize,
                    )
                };
                if let Some(note_end) = p_offset.checked_add(p_filesz) {
                    if note_end <= bytes.len() {
                        parse_elf_notes(&bytes[p_offset..note_end], le, is_64bit, &mut info);
                    }
                }
            }
        }
    }

    info
}

fn map_macho_cputype(cputype: u32) -> BinaryArch {
    match cputype {
        0x0100_000C => BinaryArch::Arm64,
        0x0100_0007 => BinaryArch::X64,
        12 => BinaryArch::Arm32,
        7 => BinaryArch::X86,
        other => BinaryArch::Unknown(other),
    }
}

fn is_plausible_macho_cputype(cputype: u32) -> bool {
    matches!(
        cputype,
        0x0100_000C | 0x0200_000C | 0x0100_0007 | 7 | 12 | 18 | 0x0100_0012
    )
}

fn inspect_macho_bytes(bytes: &[u8]) -> Option<BinaryInfo> {
    if bytes.len() < 28 {
        return None;
    }
    let m4 = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let (is_64bit, le) = match m4 {
        [0xCF, 0xFA, 0xED, 0xFE] => (true, true),   // MH_MAGIC_64 LE
        [0xFE, 0xED, 0xFA, 0xCF] => (true, false),  // MH_MAGIC_64 BE
        [0xCE, 0xFA, 0xED, 0xFE] => (false, true),  // MH_MAGIC LE
        [0xFE, 0xED, 0xFA, 0xCE] => (false, false), // MH_MAGIC BE
        _ => return None,
    };
    if is_64bit && bytes.len() < 32 {
        return None;
    }
    let cputype = read_u32(bytes, 4, le)?;
    let flags = read_u32(bytes, 24, le)?;
    let arch = map_macho_cputype(cputype);
    Some(BinaryInfo {
        format: BinaryFormat::MachO,
        arches: vec![arch],
        is_64bit,
        has_pie_or_aslr: (flags & 0x0020_0000) != 0, // MH_PIE
        has_nx_stack: (flags & 0x0002_0000) == 0,    // !MH_ALLOW_STACK_EXECUTION
        has_cfg_or_relro: false,
        has_bti: false,
        has_pac: false,
        has_cet_ibt: false,
        has_cet_shstk: false,
    })
}

fn inspect_macho_fat_bytes(bytes: &[u8]) -> Option<BinaryInfo> {
    if bytes.len() < 8 {
        return None;
    }
    let m4 = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let (is_fat64, be) = match m4 {
        [0xCA, 0xFE, 0xBA, 0xBE] => (false, true),
        [0xBE, 0xBA, 0xFE, 0xCA] => (false, false),
        [0xCA, 0xFE, 0xBA, 0xBF] => (true, true),
        [0xBF, 0xBA, 0xFE, 0xCA] => (true, false),
        _ => return None,
    };
    let le = !be;
    let nfat = read_u32(bytes, 4, le)? as usize;
    if nfat == 0 || nfat > 16 {
        return None;
    }
    let entry_sz = if is_fat64 { 32 } else { 20 };
    let table_end = 8usize.checked_add(nfat.checked_mul(entry_sz)?)?;
    if bytes.len() < table_end {
        return None;
    }
    let mut arches = Vec::with_capacity(nfat);
    let mut any_64 = false;
    for i in 0..nfat {
        let off = 8 + i * entry_sz;
        let cputype = read_u32(bytes, off, le)?;
        if !is_plausible_macho_cputype(cputype) {
            return None;
        }
        let align = if is_fat64 {
            read_u32(bytes, off + 24, le)?
        } else {
            read_u32(bytes, off + 16, le)?
        };
        if align > 30 {
            return None;
        }
        let arch = map_macho_cputype(cputype);
        if matches!(arch, BinaryArch::Arm64 | BinaryArch::X64 | BinaryArch::RiscV64) {
            any_64 = true;
        }
        if !arches.contains(&arch) {
            arches.push(arch);
        }
    }
    Some(BinaryInfo {
        format: BinaryFormat::MachOUniversal,
        arches,
        is_64bit: any_64,
        has_pie_or_aslr: true,
        has_nx_stack: true,
        has_cfg_or_relro: false,
        has_bti: false,
        has_pac: false,
        has_cet_ibt: false,
        has_cet_shstk: false,
    })
}

pub fn inspect_binary_bytes(bytes: &[u8]) -> BinaryInfo {
    if bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z' {
        let pe = inspect_pe_bytes(bytes);
        if pe.class != PeClass::NotPe {
            let arch = match pe.class {
                PeClass::Amd64 => BinaryArch::X64,
                PeClass::Arm64 => BinaryArch::Arm64,
                PeClass::Arm64Ec => BinaryArch::Arm64Ec,
                PeClass::I386 => BinaryArch::X86,
                PeClass::UnknownMachine(m) => BinaryArch::Unknown(u32::from(m)),
                PeClass::NotPe => BinaryArch::Unknown(0),
            };
            return BinaryInfo {
                format: BinaryFormat::Pe,
                arches: vec![arch],
                is_64bit: pe.is_pe32_plus,
                has_pie_or_aslr: pe.has_aslr,
                has_nx_stack: pe.has_dep_nx,
                has_cfg_or_relro: pe.has_cfg,
                has_bti: false,
                has_pac: false,
                has_cet_ibt: false,
                has_cet_shstk: false,
            };
        }
    }

    if bytes.len() >= 52 && &bytes[0..4] == b"\x7fELF" {
        return inspect_elf_bytes(bytes);
    }

    if let Some(macho) = inspect_macho_bytes(bytes) {
        return macho;
    }

    if let Some(fat) = inspect_macho_fat_bytes(bytes) {
        return fat;
    }

    BinaryInfo::script_or_raw()
}

pub fn inspect_binary_file(path: &Path) -> Result<BinaryInfo, CoreError> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 16384];
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = file.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(inspect_binary_bytes(&buf[..filled]))
}

pub fn validate_binary_policy(
    info: &BinaryInfo,
    host_os: TargetOs,
    host_arch: TargetArch,
    mode: ArchExecutionMode,
) -> ArchValidation {
    if info.format == BinaryFormat::ScriptOrRaw {
        return ArchValidation {
            allowed: false,
            requires_prism_emulation: false,
            suppress_acg_for_emulation: false,
            reason: "non-executable script or raw file rejected by binary preflight".to_string(),
        };
    }

    match host_os {
        TargetOs::Windows => {
            if info.format != BinaryFormat::Pe {
                return ArchValidation {
                    allowed: false,
                    requires_prism_emulation: false,
                    suppress_acg_for_emulation: false,
                    reason: format!("binary format {:?} rejected on Windows (PE required)", info.format),
                };
            }
            validate_architecture_policy(info.to_pe_class(), host_arch, mode)
        }
        TargetOs::MacOs => {
            if !matches!(
                info.format,
                BinaryFormat::MachO | BinaryFormat::MachOUniversal
            ) {
                return ArchValidation {
                    allowed: false,
                    requires_prism_emulation: false,
                    suppress_acg_for_emulation: false,
                    reason: format!("binary format {:?} rejected on macOS (Mach-O required)", info.format),
                };
            }
            match host_arch {
                TargetArch::Arm64 => {
                    if info.arches.contains(&BinaryArch::Arm64) {
                        ArchValidation {
                            allowed: true,
                            requires_prism_emulation: false,
                            suppress_acg_for_emulation: false,
                            reason: "native ARM64 Mach-O allowed on macos-arm64".to_string(),
                        }
                    } else if info.arches.contains(&BinaryArch::X64) {
                        if mode == ArchExecutionMode::AllowPrismX64 {
                            ArchValidation {
                                allowed: true,
                                requires_prism_emulation: true,
                                suppress_acg_for_emulation: true,
                                reason: "x86_64 Mach-O permitted under Apple Rosetta 2 emulation".to_string(),
                            }
                        } else {
                            ArchValidation {
                                allowed: false,
                                requires_prism_emulation: true,
                                suppress_acg_for_emulation: true,
                                reason: "Rosetta 2 x64 emulation blocked by default on macos-arm64 (set mode = \"allow_prism_x64\" to permit)".to_string(),
                            }
                        }
                    } else {
                        ArchValidation {
                            allowed: false,
                            requires_prism_emulation: false,
                            suppress_acg_for_emulation: false,
                            reason: format!("Mach-O arches {:?} rejected on macos-arm64", info.arches),
                        }
                    }
                }
                TargetArch::X64 => {
                    if info.arches.contains(&BinaryArch::X64) {
                        ArchValidation {
                            allowed: true,
                            requires_prism_emulation: false,
                            suppress_acg_for_emulation: false,
                            reason: "native x86_64 Mach-O allowed on macos-x64".to_string(),
                        }
                    } else {
                        ArchValidation {
                            allowed: false,
                            requires_prism_emulation: false,
                            suppress_acg_for_emulation: false,
                            reason: format!("Mach-O arches {:?} rejected on macos-x64", info.arches),
                        }
                    }
                }
            }
        }
        TargetOs::Linux | TargetOs::FreeBsd | TargetOs::Other => {
            if info.format != BinaryFormat::Elf {
                return ArchValidation {
                    allowed: false,
                    requires_prism_emulation: false,
                    suppress_acg_for_emulation: false,
                    reason: format!(
                        "binary format {:?} rejected on {} (ELF required)",
                        info.format,
                        host_os.as_str()
                    ),
                };
            }
            match host_arch {
                TargetArch::Arm64 => {
                    if info.arches.contains(&BinaryArch::Arm64) {
                        ArchValidation {
                            allowed: true,
                            requires_prism_emulation: false,
                            suppress_acg_for_emulation: false,
                            reason: format!(
                                "native AArch64 ELF allowed on {}-arm64",
                                host_os.as_str()
                            ),
                        }
                    } else if info.arches.contains(&BinaryArch::X64) {
                        if mode == ArchExecutionMode::AllowPrismX64 {
                            ArchValidation {
                                allowed: true,
                                requires_prism_emulation: true,
                                suppress_acg_for_emulation: true,
                                reason: format!(
                                    "x86_64 ELF permitted under binfmt/QEMU/FEX emulation on {}-arm64",
                                    host_os.as_str()
                                ),
                            }
                        } else {
                            ArchValidation {
                                allowed: false,
                                requires_prism_emulation: true,
                                suppress_acg_for_emulation: true,
                                reason: format!(
                                    "binfmt/QEMU/FEX x64 emulation blocked by default on {}-arm64 (set mode = \"allow_prism_x64\" to permit)",
                                    host_os.as_str()
                                ),
                            }
                        }
                    } else {
                        ArchValidation {
                            allowed: false,
                            requires_prism_emulation: false,
                            suppress_acg_for_emulation: false,
                            reason: format!(
                                "ELF arches {:?} rejected on {}-arm64",
                                info.arches,
                                host_os.as_str()
                            ),
                        }
                    }
                }
                TargetArch::X64 => {
                    if info.arches.contains(&BinaryArch::X64) {
                        ArchValidation {
                            allowed: true,
                            requires_prism_emulation: false,
                            suppress_acg_for_emulation: false,
                            reason: format!(
                                "native x86_64 ELF allowed on {}-x64",
                                host_os.as_str()
                            ),
                        }
                    } else {
                        ArchValidation {
                            allowed: false,
                            requires_prism_emulation: false,
                            suppress_acg_for_emulation: false,
                            reason: format!(
                                "ELF arches {:?} rejected on {}-x64",
                                info.arches,
                                host_os.as_str()
                            ),
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_elf64(machine: u16, prop_type: u32, prop_flags: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB
        buf[6] = 1;
        buf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        buf[18..20].copy_from_slice(&machine.to_le_bytes());
        buf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
        buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize = 56
        buf[56..58].copy_from_slice(&3u16.to_le_bytes()); // e_phnum = 3

        // Phdr 0: PT_GNU_STACK (RW only -> NX)
        let p0 = 64;
        buf[p0..p0 + 4].copy_from_slice(&0x6474_E551u32.to_le_bytes());
        buf[p0 + 4..p0 + 8].copy_from_slice(&6u32.to_le_bytes());

        // Phdr 1: PT_GNU_RELRO
        let p1 = 64 + 56;
        buf[p1..p1 + 4].copy_from_slice(&0x6474_E552u32.to_le_bytes());
        buf[p1 + 4..p1 + 8].copy_from_slice(&4u32.to_le_bytes());

        // Phdr 2: PT_NOTE at offset 256, size 32
        let p2 = 64 + 112;
        buf[p2..p2 + 4].copy_from_slice(&4u32.to_le_bytes());
        buf[p2 + 8..p2 + 16].copy_from_slice(&256u64.to_le_bytes());
        buf[p2 + 32..p2 + 40].copy_from_slice(&32u64.to_le_bytes());

        let n = 256;
        buf[n..n + 4].copy_from_slice(&4u32.to_le_bytes()); // namesz = 4
        buf[n + 4..n + 8].copy_from_slice(&16u32.to_le_bytes()); // descsz = 16
        buf[n + 8..n + 12].copy_from_slice(&5u32.to_le_bytes()); // NT_GNU_PROPERTY_TYPE_0
        buf[n + 12..n + 16].copy_from_slice(b"GNU\0");
        buf[n + 16..n + 20].copy_from_slice(&prop_type.to_le_bytes());
        buf[n + 20..n + 24].copy_from_slice(&4u32.to_le_bytes());
        buf[n + 24..n + 28].copy_from_slice(&prop_flags.to_le_bytes());
        buf
    }

    fn synthetic_macho64(cputype: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // MH_MAGIC_64 LE
        buf[4..8].copy_from_slice(&cputype.to_le_bytes());
        buf[24..28].copy_from_slice(&0x0020_0000u32.to_le_bytes()); // MH_PIE
        buf
    }

    fn synthetic_macho_universal(cputypes: &[u32]) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + cputypes.len() * 20];
        buf[0..4].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        buf[4..8].copy_from_slice(&(cputypes.len() as u32).to_be_bytes());
        for (i, &cpu) in cputypes.iter().enumerate() {
            let off = 8 + i * 20;
            buf[off..off + 4].copy_from_slice(&cpu.to_be_bytes());
            buf[off + 8..off + 12].copy_from_slice(&4096u32.to_be_bytes());
            buf[off + 12..off + 16].copy_from_slice(&1024u32.to_be_bytes());
            buf[off + 16..off + 20].copy_from_slice(&14u32.to_be_bytes());
        }
        buf
    }

    #[test]
    fn parses_elf64_arm64_and_x64_properties() {
        let arm_elf = inspect_binary_bytes(&synthetic_elf64(183, 0xC000_0000, 0x3));
        assert_eq!(arm_elf.format, BinaryFormat::Elf);
        assert_eq!(arm_elf.arches, vec![BinaryArch::Arm64]);
        assert!(arm_elf.is_64bit);
        assert!(arm_elf.has_pie_or_aslr);
        assert!(arm_elf.has_nx_stack);
        assert!(arm_elf.has_cfg_or_relro);
        assert!(arm_elf.has_bti);
        assert!(arm_elf.has_pac);

        let x64_elf = inspect_binary_bytes(&synthetic_elf64(62, 0xC000_0002, 0x3));
        assert_eq!(x64_elf.format, BinaryFormat::Elf);
        assert_eq!(x64_elf.arches, vec![BinaryArch::X64]);
        assert!(x64_elf.has_cet_ibt);
        assert!(x64_elf.has_cet_shstk);
    }

    #[test]
    fn parses_macho_and_universal_and_enforces_emulation_gates() {
        let macho_arm = inspect_binary_bytes(&synthetic_macho64(0x0100_000C));
        assert_eq!(macho_arm.format, BinaryFormat::MachO);
        assert_eq!(macho_arm.arches, vec![BinaryArch::Arm64]);
        assert!(macho_arm.has_pie_or_aslr);
        assert!(macho_arm.has_nx_stack);

        let fat = inspect_binary_bytes(&synthetic_macho_universal(&[0x0100_0007, 0x0100_000C]));
        assert_eq!(fat.format, BinaryFormat::MachOUniversal);
        assert!(fat.arches.contains(&BinaryArch::Arm64));
        assert!(fat.arches.contains(&BinaryArch::X64));

        assert!(
            validate_binary_policy(
                &fat,
                TargetOs::MacOs,
                TargetArch::Arm64,
                ArchExecutionMode::StrictNative
            )
            .allowed
        );

        let macho_x64 = inspect_binary_bytes(&synthetic_macho64(0x0100_0007));
        let rosetta_deny = validate_binary_policy(
            &macho_x64,
            TargetOs::MacOs,
            TargetArch::Arm64,
            ArchExecutionMode::StrictNative,
        );
        assert!(!rosetta_deny.allowed);
        assert!(rosetta_deny.requires_prism_emulation);

        let rosetta_allow = validate_binary_policy(
            &macho_x64,
            TargetOs::MacOs,
            TargetArch::Arm64,
            ArchExecutionMode::AllowPrismX64,
        );
        assert!(rosetta_allow.allowed);
        assert!(rosetta_allow.requires_prism_emulation);

        let x64_elf = inspect_binary_bytes(&synthetic_elf64(62, 0xC000_0002, 0x3));
        assert!(
            !validate_binary_policy(
                &x64_elf,
                TargetOs::Linux,
                TargetArch::Arm64,
                ArchExecutionMode::StrictNative
            )
            .allowed
        );
        assert!(
            validate_binary_policy(
                &x64_elf,
                TargetOs::Linux,
                TargetArch::Arm64,
                ArchExecutionMode::AllowPrismX64
            )
            .allowed
        );
    }
}
