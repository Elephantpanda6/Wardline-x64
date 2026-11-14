const std = @import("std");
const common = @import("common");
const w = common.win32;
const sandbox = common.sandbox;

fn checkHcsAvailable() u8 {
    const dll_w = std.unicode.wtf8ToWtf16LeStringLiteral("computecore.dll");
    if (w.LoadLibraryW(dll_w)) |h| {
        _ = w.FreeLibrary(h);
        return 1;
    }
    return 0;
}

fn checkCetShadowStackSupported() u8 {
    var policy: u32 = 0;
    if (w.GetProcessMitigationPolicy(w.GetCurrentProcess(), w.ProcessUserShadowStackPolicy, &policy, @sizeOf(u32)) != w.FALSE) {
        if ((policy & 0x1) != 0) return 1;
    }
    return 0;
}

export fn wl_engine_abi_version() callconv(.c) u32 {
    return common.abi_version;
}

export fn wl_engine_arch() callconv(.c) u32 {
    return @intFromEnum(common.WlArch.x64);
}

export fn wl_classify_pe(bytes_ptr: ?[*]const u8, bytes_len: usize) callconv(.c) u32 {
    const ptr = bytes_ptr orelse return @intFromEnum(common.WlPeClass.unknown);
    return @intFromEnum(common.classifyPeBytes(ptr[0..bytes_len]));
}

export fn wl_probe_capabilities(out_caps: ?*common.WlHostCapabilities) callconv(.c) u32 {
    const caps = out_caps orelse return @intFromEnum(common.WlStatusCode.invalid_arg);

    var sys_info = std.mem.zeroes(w.SYSTEM_INFO);
    w.GetNativeSystemInfo(&sys_info);

    var os_ver = std.mem.zeroes(w.OSVERSIONINFOW);
    os_ver.dwOSVersionInfoSize = @sizeOf(w.OSVERSIONINFOW);
    _ = w.RtlGetVersion(&os_ver);

    var proc_machine: w.WORD = 0;
    var native_machine: w.WORD = 0;
    _ = w.IsWow64Process2(w.GetCurrentProcess(), &proc_machine, &native_machine);

    caps.* = .{
        .arch = @intFromEnum(common.WlArch.x64),
        .abi_version = common.abi_version,
        .is_wow64_emulated = if (proc_machine != 0) 1 else 0,
        .cet_shadow_stack_supported = checkCetShadowStackSupported(),
        .pac_bti_available = 0,
        .hyperv_hcs_available = checkHcsAvailable(),
        .appcontainer_supported = if (os_ver.dwBuildNumber >= 9200 or os_ver.dwMajorVersion >= 10) 1 else 0,
        .job_object_iocp_supported = 1,
        .reserved = .{ 0, 0 },
        .os_build_number = os_ver.dwBuildNumber,
        .page_size = sys_info.dwPageSize,
    };
    return @intFromEnum(common.WlStatusCode.ok);
}

export fn wl_spawn_isolated(
    req_opt: ?*const common.WlSpawnRequest,
    io_opt: ?*common.WlIoBuffers,
    res_opt: ?*common.WlSpawnResult,
) callconv(.c) u32 {
    const req = req_opt orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const io = io_opt orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const res = res_opt orelse return @intFromEnum(common.WlStatusCode.invalid_arg);

    const exe_slice = if (req.executable_utf8) |p| p[0..req.executable_len] else "";
    const pe_class = sandbox.inspectExecutablePeOnDisk(exe_slice);
    if (pe_class != .amd64) {
        res.* = std.mem.zeroes(common.WlSpawnResult);
        common.writeDetail(io, res, "win-x64 engine only permits native AMD64 (0x8664) PE images");
        res.status_code = @intFromEnum(common.WlStatusCode.pe_disallowed_arch);
        return res.status_code;
    }

    var word0: u64 =
        w.MITIGATION_DEP_ENABLE |
        w.MITIGATION_SEHOP_ENABLE |
        w.MITIGATION_FORCE_RELOCATE_IMAGES_ALWAYS_ON |
        w.MITIGATION_HEAP_TERMINATE_ALWAYS_ON |
        w.MITIGATION_BOTTOM_UP_ASLR_ALWAYS_ON |
        w.MITIGATION_HIGH_ENTROPY_ASLR_ALWAYS_ON |
        w.MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON |
        w.MITIGATION_FONT_DISABLE_ALWAYS_ON;

    const acg_on = req.enable_acg != 0;
    if (acg_on) {
        word0 |= w.MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    }

    var word1: u64 = 0;
    var qwords: usize = 1;
    if (req.enable_cet != 0 and checkCetShadowStackSupported() != 0) {
        word1 |= w.MITIGATION2_CET_USER_SHADOW_STACKS_ALWAYS_ON;
        qwords = 2;
    }

    return sandbox.executeIsolatedChild(
        req,
        io,
        res,
        .{ word0, word1 },
        qwords,
        false,
        acg_on,
    );
}

export fn wl_create_hardened_pipe(
    name_utf8: ?[*]const u8,
    name_len: usize,
    out_handle: ?*usize,
    out_win32_err: ?*u32,
) callconv(.c) u32 {
    const ptr = name_utf8 orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const h = out_handle orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const e = out_win32_err orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    return sandbox.createHardenedPipeImpl(ptr[0..name_len], h, e);
}

export fn wl_set_owner_only_dacl_utf8(
    path_utf8: ?[*]const u8,
    path_len: usize,
    is_dir: u8,
    out_win32_err: ?*u32,
) callconv(.c) u32 {
    _ = is_dir;
    const ptr = path_utf8 orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const e = out_win32_err orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    return sandbox.setOwnerOnlyDaclImpl(ptr[0..path_len], e);
}

export fn wl_harden_current_process_dacl(out_win32_err: ?*u32) callconv(.c) u32 {
    const e = out_win32_err orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    return sandbox.hardenCurrentProcessDaclImpl(e);
}

test "win-x64 probe reports x64 host capabilities cleanly" {
    var caps: common.WlHostCapabilities = undefined;
    try std.testing.expectEqual(@intFromEnum(common.WlStatusCode.ok), wl_probe_capabilities(&caps));
    try std.testing.expectEqual(@intFromEnum(common.WlArch.x64), caps.arch);
    try std.testing.expect(caps.os_build_number > 0);
    try std.testing.expectEqual(@as(u32, 4096), caps.page_size);
}
