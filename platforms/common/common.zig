const std = @import("std");
pub const win32 = @import("win32_ffi.zig");
pub const sandbox = @import("sandbox_core.zig");

pub const abi_version: u32 = 1;

pub const WlArch = enum(u32) {
    unknown = 0,
    x64 = 1,
    arm64 = 2,
};

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
    reserved: [2]u8,
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
