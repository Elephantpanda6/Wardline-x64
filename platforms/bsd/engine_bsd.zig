const std = @import("std");
const builtin = @import("builtin");
const common = @import("common");
const px = common.posix;
const c = std.c;

extern "c" fn cap_enter() c_int;
extern "c" fn fexecve(
    fd: c_int,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) c_int;

fn bsdPreExec(
    ctx: *const px.PreExecContext,
    argv_ptrs: [*:null]const ?[*:0]const u8,
    envp_ptrs: [*:null]const ?[*:0]const u8,
) px.PreExecResult {
    if (ctx.isolation_level == @intFromEnum(common.WlIsolationLevel.l0_restricted_job)) {
        return .{};
    }

    if (builtin.os.tag == .freebsd) {
        var flags: c.O = .{};
        flags.EXEC = true;
        flags.CLOEXEC = true;
        const exe_fd = c.open(ctx.exe_path_z, flags);
        if (exe_fd < 0) {
            return .{
                .status = .spawn,
                .errno_val = px.lastErrno(),
                .detail = "open(O_EXEC) before cap_enter failed",
            };
        }
        if (cap_enter() != 0) {
            const err = px.lastErrno();
            _ = c.close(exe_fd);
            return .{
                .status = .appcontainer,
                .errno_val = err,
                .detail = "FreeBSD cap_enter() failed",
            };
        }
        _ = fexecve(exe_fd, argv_ptrs, envp_ptrs);
        const err = px.lastErrno();
        _ = c.close(exe_fd);
        return .{
            .status = .spawn,
            .errno_val = err,
            .detail = "FreeBSD fexecve() after cap_enter failed",
        };
    }

    return .{};
}

export fn wl_engine_abi_version() callconv(.c) u32 {
    return common.abi_version;
}

export fn wl_engine_arch() callconv(.c) u32 {
    return if (builtin.cpu.arch == .aarch64)
        @intFromEnum(common.WlArch.arm64)
    else
        @intFromEnum(common.WlArch.x64);
}

export fn wl_classify_pe(bytes_ptr: ?[*]const u8, bytes_len: usize) callconv(.c) u32 {
    const ptr = bytes_ptr orelse return @intFromEnum(common.WlPeClass.unknown);
    return @intFromEnum(common.classifyBinaryBytes(ptr[0..bytes_len]).arch);
}

export fn wl_probe_capabilities(out_caps: ?*common.WlHostCapabilities) callconv(.c) u32 {
    const caps = common.validateCapsPtr(out_caps) orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const psize = px.pageSize();
    const bhyve_ok: u8 = if (c.access("/dev/vmm", 0) == 0) 1 else 0;
    const os_kind: common.WlOsKind = if (builtin.os.tag == .freebsd) .freebsd else .other_unix;

    var tier_mask: u32 = common.WL_TIER_BIT_L0;
    var feat: u64 = 0;
    if (builtin.os.tag == .freebsd) {
        tier_mask |= common.WL_TIER_BIT_L1;
        feat |= common.WL_FEAT_FREEBSD_CAPSICUM;
    }
    if (bhyve_ok != 0) {
        tier_mask |= common.WL_TIER_BIT_L2;
        feat |= common.WL_FEAT_FREEBSD_BHYVE;
    }

    caps.* = .{
        .struct_size = @sizeOf(common.WlHostCapabilities),
        .abi_version = common.abi_version,
        .arch = wl_engine_arch(),
        .os_build_number = 0,
        .page_size = psize,
        .tier_support_mask = tier_mask,
        .feature_flags = feat,
        .is_wow64_emulated = 0,
        .cet_shadow_stack_supported = 0,
        .pac_bti_available = 0,
        .hyperv_hcs_available = bhyve_ok,
        .appcontainer_supported = 1,
        .job_object_iocp_supported = 1,
        .os_kind = @intFromEnum(os_kind),
        .arm64_ext_flags = if (builtin.cpu.arch == .aarch64 and psize > 4096) common.WL_ARM64_FEAT_LARGE_PAGES else 0,
        .landlock_abi = 0,
        .cgroup_v2_available = 0,
        .reserved = @splat(0),
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

    if (!common.validateSpawnReq(req, io, res)) {
        return res.status_code;
    }

    const exe_slice = if (req.executable_utf8) |p| p[0..req.executable_len] else "";
    const bin_info = px.inspectExecutableOnDisk(exe_slice);
    if (bin_info.format != .elf) {
        res.* = std.mem.zeroes(common.WlSpawnResult);
        res.struct_size = @sizeOf(common.WlSpawnResult);
        common.writeDetail(io, res, "non-ELF image rejected on BSD/POSIX");
        res.status_code = @intFromEnum(common.WlStatusCode.pe_disallowed_arch);
        return res.status_code;
    }

    const host_is_arm64 = builtin.cpu.arch == .aarch64;
    if (host_is_arm64 and !bin_info.has_arm64) {
        res.* = std.mem.zeroes(common.WlSpawnResult);
        res.struct_size = @sizeOf(common.WlSpawnResult);
        common.writeDetail(io, res, "non-ARM64 ELF rejected on bsd-arm64");
        res.status_code = @intFromEnum(common.WlStatusCode.pe_disallowed_arch);
        return res.status_code;
    }
    if (!host_is_arm64 and !bin_info.has_amd64) {
        res.* = std.mem.zeroes(common.WlSpawnResult);
        res.struct_size = @sizeOf(common.WlSpawnResult);
        common.writeDetail(io, res, "non-x64 ELF rejected on bsd-x64");
        res.status_code = @intFromEnum(common.WlStatusCode.pe_disallowed_arch);
        return res.status_code;
    }

    return px.executePosixIsolated(req, io, res, bsdPreExec, false, null);
}

export fn wl_create_hardened_pipe(
    _: ?[*]const u8,
    _: usize,
    _: ?*usize,
    out_win32_err: ?*u32,
) callconv(.c) u32 {
    if (out_win32_err) |e| e.* = 0;
    return @intFromEnum(common.WlStatusCode.not_supported_arch);
}

export fn wl_set_owner_only_dacl_utf8(
    path_utf8: ?[*]const u8,
    path_len: usize,
    is_dir: u8,
    out_win32_err: ?*u32,
) callconv(.c) u32 {
    const ptr = path_utf8 orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const e = out_win32_err orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    return px.setOwnerOnlyMode(ptr[0..path_len], is_dir != 0, e);
}

export fn wl_harden_current_process_dacl(out_win32_err: ?*u32) callconv(.c) u32 {
    const e = out_win32_err orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    return px.hardenProcessCommon(e);
}
