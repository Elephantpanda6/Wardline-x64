const std = @import("std");
const builtin = @import("builtin");

pub const win32 = if (builtin.os.tag == .windows) @import("win32_ffi.zig") else struct {};
pub const sandbox = if (builtin.os.tag == .windows) @import("sandbox_core.zig") else struct {};
pub const posix = if (builtin.os.tag != .windows) @import("posix_sandbox.zig") else struct {};

pub const abi_version: u32 = 1;

pub const WlArch = enum(u32) {
    unknown = 0,
    x64 = 1,
    arm64 = 2,
};

pub const WlOsKind = enum(u8) {
    unknown = 0,
    windows = 1,
    linux = 2,
    macos = 3,
    freebsd = 4,
    other_unix = 5,
};

pub const WL_ARM64_FEAT_PAC: u8 = 0x01;
pub const WL_ARM64_FEAT_BTI: u8 = 0x02;
pub const WL_ARM64_FEAT_MTE: u8 = 0x04;
pub const WL_ARM64_FEAT_SVE: u8 = 0x08;
pub const WL_ARM64_FEAT_SVE2: u8 = 0x10;
pub const WL_ARM64_FEAT_LARGE_PAGES: u8 = 0x20;

pub const WlIsolationLevel = enum(u32) {
    l0_restricted_job = 0,
    l1_appcontainer = 1,
    l2_microvm = 2,
};

pub const WlPeClass = enum(u32) {
    unknown = 0,
    amd64 = 1,
    arm64 = 2,
    arm64ec = 3,
    x86 = 4,
    script_or_raw = 5,
};

pub const WlBinaryFormat = enum(u8) {
    unknown = 0,
    pe = 1,
    elf = 2,
    macho = 3,
    macho_universal = 4,
    script_or_raw = 5,
};

pub const WlBinaryInfo = struct {
    format: WlBinaryFormat,
    arch: WlPeClass,
    has_arm64: bool,
    has_amd64: bool,
};

pub const WlStatusCode = enum(u32) {
    ok = 0,
    invalid_arg = 1,
    not_supported_arch = 2,
    pe_invalid = 3,
    pe_disallowed_arch = 4,
    prism_blocked = 5,
    job_creation = 6,
    token_restriction = 7,
    appcontainer = 8,
    spawn = 9,
    timeout_killed = 10,
    pipe = 11,
    acl = 12,
    probe = 13,
    memory_limit = 14,
    io = 15,
};

pub const WlHostCapabilities = extern struct {
    arch: u32,
    abi_version: u32,
    is_wow64_emulated: u8,
    cet_shadow_stack_supported: u8,
    pac_bti_available: u8,
    hyperv_hcs_available: u8,
    appcontainer_supported: u8,
    job_object_iocp_supported: u8,
    os_kind: u8,
    arm64_ext_flags: u8,
    os_build_number: u32,
    page_size: u32,
};

pub const WlSpawnRequest = extern struct {
    executable_utf8: ?[*]const u8,
    executable_len: usize,
    cmdline_utf8: ?[*]const u8,
    cmdline_len: usize,
    working_dir_utf8: ?[*]const u8,
    working_dir_len: usize,
    env_block_utf8: ?[*]const u8,
    env_block_len: usize,
    container_name_utf8: ?[*]const u8,
    container_name_len: usize,
    rw_paths_utf8: ?[*]const u8,
    rw_paths_len: usize,
    ro_paths_utf8: ?[*]const u8,
    ro_paths_len: usize,
    isolation_level: u32,
    timeout_ms: u32,
    max_memory_bytes: u64,
    max_processes: u32,
    cpu_rate_percent: u32,
    allow_prism_x64: u8,
    allow_arm64ec: u8,
    enable_acg: u8,
    enable_cet: u8,
    capture_output: u8,
    reserved: [3]u8,
};

pub const WlIoBuffers = extern struct {
    stdout_ptr: ?[*]u8,
    stdout_cap: usize,
    stderr_ptr: ?[*]u8,
    stderr_cap: usize,
    detail_ptr: ?[*]u8,
    detail_cap: usize,
};

pub const WlSpawnResult = extern struct {
    status_code: u32,
    win32_error: u32,
    exit_code: u32,
    timed_out: u8,
    oom_killed: u8,
    emulation_detected: u8,
    acg_applied: u8,
    pid: u32,
    peak_memory_bytes: u64,
    cpu_time_us: u64,
    stdout_len: usize,
    stderr_len: usize,
    detail_len: usize,
};

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
pub const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xA641;

pub fn classifyPeBytes(bytes: []const u8) WlPeClass {
    if (bytes.len < 64) return .script_or_raw;
    if (bytes[0] != 'M' or bytes[1] != 'Z') return .script_or_raw;
    const pe_offset: usize = std.mem.readInt(u32, bytes[0x3C..0x40], .little);
    if (pe_offset > bytes.len or bytes.len - pe_offset < 24) return .unknown;
    if (!std.mem.eql(u8, bytes[pe_offset .. pe_offset + 4], "PE\x00\x00")) {
        return .unknown;
    }
    const machine = std.mem.readInt(u16, bytes[pe_offset + 4 ..][0..2], .little);
    return switch (machine) {
        IMAGE_FILE_MACHINE_AMD64 => .amd64,
        IMAGE_FILE_MACHINE_ARM64 => .arm64,
        IMAGE_FILE_MACHINE_ARM64EC => .arm64ec,
        IMAGE_FILE_MACHINE_I386 => .x86,
        else => .unknown,
    };
}

pub fn classifyElfBytes(bytes: []const u8) WlPeClass {
    if (bytes.len < 20 or !std.mem.eql(u8, bytes[0..4], "\x7fELF")) return .unknown;
    const ei_data = bytes[5];
    const endian: std.builtin.Endian = switch (ei_data) {
        1 => .little,
        2 => .big,
        else => return .unknown,
    };
    const e_machine = std.mem.readInt(u16, bytes[18..20], endian);
    return switch (e_machine) {
        183 => .arm64,
        62 => .amd64,
        3 => .x86,
        else => .unknown,
    };
}

fn mapMachoCpuType(cputype: u32) WlPeClass {
    return switch (cputype) {
        0x0100_000C => .arm64,
        0x0100_0007 => .amd64,
        7 => .x86,
        else => .unknown,
    };
}

pub fn classifyMachOBytes(bytes: []const u8) WlBinaryInfo {
    if (bytes.len >= 28) {
        const m4 = bytes[0..4];
        const endian_opt: ?std.builtin.Endian = if (std.mem.eql(u8, m4, &.{ 0xCF, 0xFA, 0xED, 0xFE }) or
            std.mem.eql(u8, m4, &.{ 0xCE, 0xFA, 0xED, 0xFE }))
            .little
        else if (std.mem.eql(u8, m4, &.{ 0xFE, 0xED, 0xFA, 0xCF }) or
            std.mem.eql(u8, m4, &.{ 0xFE, 0xED, 0xFA, 0xCE }))
            .big
        else
            null;
        if (endian_opt) |endian| {
            const cpu = std.mem.readInt(u32, bytes[4..8], endian);
            const cls = mapMachoCpuType(cpu);
            return .{
                .format = .macho,
                .arch = cls,
                .has_arm64 = cls == .arm64,
                .has_amd64 = cls == .amd64,
            };
        }
    }

    if (bytes.len >= 8) {
        const m4 = bytes[0..4];
        const fat_info: ?struct { fat64: bool, endian: std.builtin.Endian } = if (std.mem.eql(u8, m4, &.{ 0xCA, 0xFE, 0xBA, 0xBE }))
            .{ .fat64 = false, .endian = .big }
        else if (std.mem.eql(u8, m4, &.{ 0xBE, 0xBA, 0xFE, 0xCA }))
            .{ .fat64 = false, .endian = .little }
        else if (std.mem.eql(u8, m4, &.{ 0xCA, 0xFE, 0xBA, 0xBF }))
            .{ .fat64 = true, .endian = .big }
        else if (std.mem.eql(u8, m4, &.{ 0xBF, 0xBA, 0xFE, 0xCA }))
            .{ .fat64 = true, .endian = .little }
        else
            null;
        if (fat_info) |fi| {
            const nfat = std.mem.readInt(u32, bytes[4..8], fi.endian);
            if (nfat >= 1 and nfat <= 16) {
                const entry_sz: usize = if (fi.fat64) 32 else 20;
                const need = 8 + @as(usize, nfat) * entry_sz;
                if (bytes.len >= need) {
                    var has_arm64 = false;
                    var has_amd64 = false;
                    var primary: WlPeClass = .unknown;
                    for (0..nfat) |i| {
                        const off = 8 + i * entry_sz;
                        const cpu = std.mem.readInt(u32, bytes[off..][0..4], fi.endian);
                        const align_v = if (fi.fat64)
                            std.mem.readInt(u32, bytes[off + 24 ..][0..4], fi.endian)
                        else
                            std.mem.readInt(u32, bytes[off + 16 ..][0..4], fi.endian);
                        if (align_v > 30) {
                            return .{ .format = .script_or_raw, .arch = .script_or_raw, .has_arm64 = false, .has_amd64 = false };
                        }
                        const cls = mapMachoCpuType(cpu);
                        if (cls == .arm64) has_arm64 = true;
                        if (cls == .amd64) has_amd64 = true;
                        if (primary == .unknown) primary = cls;
                    }
                    return .{
                        .format = .macho_universal,
                        .arch = primary,
                        .has_arm64 = has_arm64,
                        .has_amd64 = has_amd64,
                    };
                }
            }
        }
    }

    return .{
        .format = .script_or_raw,
        .arch = .script_or_raw,
        .has_arm64 = false,
        .has_amd64 = false,
    };
}

pub fn classifyBinaryBytes(bytes: []const u8) WlBinaryInfo {
    if (bytes.len >= 64 and bytes[0] == 'M' and bytes[1] == 'Z') {
        const pe_cls = classifyPeBytes(bytes);
        if (pe_cls != .script_or_raw) {
            return .{
                .format = .pe,
                .arch = pe_cls,
                .has_arm64 = pe_cls == .arm64,
                .has_amd64 = pe_cls == .amd64,
            };
        }
    }
    if (bytes.len >= 20 and std.mem.eql(u8, bytes[0..4], "\x7fELF")) {
        const elf_cls = classifyElfBytes(bytes);
        return .{
            .format = .elf,
            .arch = elf_cls,
            .has_arm64 = elf_cls == .arm64,
            .has_amd64 = elf_cls == .amd64,
        };
    }
    return classifyMachOBytes(bytes);
}

pub fn writeDetail(io: *WlIoBuffers, res: *WlSpawnResult, msg: []const u8) void {
    const ptr = io.detail_ptr orelse {
        res.detail_len = 0;
        return;
    };
    const copy_len = @min(msg.len, io.detail_cap);
    @memcpy(ptr[0..copy_len], msg[0..copy_len]);
    res.detail_len = copy_len;
}

test "classifyPeBytes detects MZ non-PE and AMD64/ARM64/ARM64EC headers" {
    var pe: [128]u8 = @splat(0);
    pe[0] = 'M';
    pe[1] = 'Z';
    std.mem.writeInt(u32, pe[0x3C..0x40], 0x40, .little);
    @memcpy(pe[0x40..0x44], "PE\x00\x00");

    std.mem.writeInt(u16, pe[0x44..0x46], IMAGE_FILE_MACHINE_AMD64, .little);
    try std.testing.expectEqual(WlPeClass.amd64, classifyPeBytes(&pe));

    std.mem.writeInt(u16, pe[0x44..0x46], IMAGE_FILE_MACHINE_ARM64, .little);
    try std.testing.expectEqual(WlPeClass.arm64, classifyPeBytes(&pe));

    std.mem.writeInt(u16, pe[0x44..0x46], IMAGE_FILE_MACHINE_ARM64EC, .little);
    try std.testing.expectEqual(WlPeClass.arm64ec, classifyPeBytes(&pe));

    const bat = "@echo off\necho hi\n";
    try std.testing.expectEqual(WlPeClass.script_or_raw, classifyPeBytes(bat));
}

test "classifyBinaryBytes detects ELF64 and Mach-O headers" {
    var elf: [64]u8 = @splat(0);
    @memcpy(elf[0..4], "\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    std.mem.writeInt(u16, elf[18..20], 183, .little);
    const elf_arm = classifyBinaryBytes(&elf);
    try std.testing.expectEqual(WlBinaryFormat.elf, elf_arm.format);
    try std.testing.expect(elf_arm.has_arm64);

    std.mem.writeInt(u16, elf[18..20], 62, .little);
    const elf_x64 = classifyBinaryBytes(&elf);
    try std.testing.expectEqual(WlBinaryFormat.elf, elf_x64.format);
    try std.testing.expect(elf_x64.has_amd64);

    var macho: [32]u8 = @splat(0);
    @memcpy(macho[0..4], &[_]u8{ 0xCF, 0xFA, 0xED, 0xFE });
    std.mem.writeInt(u32, macho[4..8], 0x0100_000C, .little);
    const m_arm = classifyBinaryBytes(&macho);
    try std.testing.expectEqual(WlBinaryFormat.macho, m_arm.format);
    try std.testing.expect(m_arm.has_arm64);

    var fat: [48]u8 = @splat(0);
    @memcpy(fat[0..4], &[_]u8{ 0xCA, 0xFE, 0xBA, 0xBE });
    std.mem.writeInt(u32, fat[4..8], 2, .big);
    std.mem.writeInt(u32, fat[8..12], 0x0100_0007, .big);
    std.mem.writeInt(u32, fat[24..28], 14, .big);
    std.mem.writeInt(u32, fat[28..32], 0x0100_000C, .big);
    std.mem.writeInt(u32, fat[44..48], 14, .big);
    const m_fat = classifyBinaryBytes(&fat);
    try std.testing.expectEqual(WlBinaryFormat.macho_universal, m_fat.format);
    try std.testing.expect(m_fat.has_arm64);
    try std.testing.expect(m_fat.has_amd64);
}
