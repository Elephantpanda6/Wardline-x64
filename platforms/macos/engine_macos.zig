const std = @import("std");
const builtin = @import("builtin");
const common = @import("common");
const px = common.posix;
const c = std.c;

extern "c" fn sandbox_init(profile: [*:0]const u8, flags: u64, errorbuf: *?[*:0]u8) c_int;
extern "c" fn sandbox_free_error(errorbuf: ?[*:0]u8) void;

fn sysctlBool(name: [*:0]const u8) bool {
    var val: c_int = 0;
    var len: usize = @sizeOf(c_int);
    if (c.sysctlbyname(name, &val, &len, null, 0) == 0) {
        return val != 0;
    }
    return false;
}

fn sysctlU32(name: [*:0]const u8) u32 {
    var val: u32 = 0;
    var len: usize = @sizeOf(u32);
    if (c.sysctlbyname(name, &val, &len, null, 0) == 0) {
        return val;
    }
    return 0;
}

fn parseDarwinRelease() u32 {
    var buf: [64]u8 = @splat(0);
    var len: usize = buf.len - 1;
    if (c.sysctlbyname("kern.osrelease", &buf, &len, null, 0) != 0) return 0;
    const raw = std.mem.trim(u8, buf[0..len], "\x00 \r\n\t");
    var it = std.mem.tokenizeScalar(u8, raw, '.');
    const maj = std.fmt.parseInt(u32, it.next() orelse "0", 10) catch 0;
    const min = std.fmt.parseInt(u32, it.next() orelse "0", 10) catch 0;
    const pat = std.fmt.parseInt(u32, it.next() orelse "0", 10) catch 0;
    return maj * 10000 + min * 100 + pat;
}

fn appendSbplExprEscaped(list: *std.ArrayList(u8), filter: []const u8, path: []const u8) !void {
    try list.append(px.alloc, '(');
    try list.appendSlice(px.alloc, filter);
    try list.appendSlice(px.alloc, " \"");
    for (path) |ch| {
        if (ch == '"' or ch == '\\') {
            try list.append(px.alloc, '\\');
        }
        try list.append(px.alloc, ch);
    }
    try list.appendSlice(px.alloc, "\")");
}

fn appendSbplWithPrivateAliases(list: *std.ArrayList(u8), filter: []const u8, path: []const u8) !void {
    try list.appendSlice(px.alloc, "  ");
    try appendSbplExprEscaped(list, filter, path);
    try list.append(px.alloc, '\n');

    if (std.mem.startsWith(u8, path, "/var/") or
        std.mem.startsWith(u8, path, "/tmp/") or
        std.mem.startsWith(u8, path, "/etc/"))
    {
        var tmp_buf: [1024]u8 = undefined;
        if (path.len + 8 <= tmp_buf.len) {
            @memcpy(tmp_buf[0..8], "/private");
            @memcpy(tmp_buf[8 .. 8 + path.len], path);
            try list.appendSlice(px.alloc, "  ");
            try appendSbplExprEscaped(list, filter, tmp_buf[0 .. 8 + path.len]);
            try list.append(px.alloc, '\n');
        }
    } else if (std.mem.startsWith(u8, path, "/private/var/") or
        std.mem.startsWith(u8, path, "/private/tmp/") or
        std.mem.startsWith(u8, path, "/private/etc/"))
    {
        try list.appendSlice(px.alloc, "  ");
        try appendSbplExprEscaped(list, filter, path[8..]);
        try list.append(px.alloc, '\n');
    }
}

fn appendSbplSubpathWithAliases(list: *std.ArrayList(u8), path: []const u8) !void {
    try appendSbplWithPrivateAliases(list, "subpath", path);
}

fn appendSbplLiteralWithAliases(list: *std.ArrayList(u8), path: []const u8) !void {
    try appendSbplWithPrivateAliases(list, "literal", path);
}

fn buildSeatbeltProfile(
    exe_slice: []const u8,
    ro_raw: []const u8,
    rw_raw: []const u8,
    single_process: bool,
) ![:0]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(px.alloc);

    if (single_process) {
        try buf.appendSlice(px.alloc, "(version 1)\n(allow default)\n(deny network*)\n(deny process-fork)\n");
    } else {
        try buf.appendSlice(px.alloc, "(version 1)\n(allow default)\n(deny network*)\n");
    }

    try buf.appendSlice(px.alloc, "(deny file-read-data)\n(allow file-read-data\n  (literal \"/\")\n");
    const sys_ro = [_][]const u8{
        "/System",
        "/usr",
        "/bin",
        "/sbin",
        "/Library",
        "/AppleInternal",
        "/dev",
        "/etc",
        "/private/etc",
        "/private/var/db",
        "/var/db",
    };
    for (sys_ro) |p| {
        try appendSbplSubpathWithAliases(&buf, p);
    }
    try appendSbplLiteralWithAliases(&buf, exe_slice);

    var ro_it = std.mem.splitScalar(u8, ro_raw, '\n');
    while (ro_it.next()) |line| {
        const p = std.mem.trim(u8, line, "\r \t");
        if (p.len == 0) continue;
        try appendSbplSubpathWithAliases(&buf, p);
    }
    var rw_ro_it = std.mem.splitScalar(u8, rw_raw, '\n');
    while (rw_ro_it.next()) |line| {
        const p = std.mem.trim(u8, line, "\r \t");
        if (p.len == 0) continue;
        try appendSbplSubpathWithAliases(&buf, p);
    }
    try buf.appendSlice(px.alloc, ")\n");

    try buf.appendSlice(px.alloc, "(deny file-write*)\n(allow file-write*\n  (literal \"/dev/null\")\n");
    var rw_it = std.mem.splitScalar(u8, rw_raw, '\n');
    while (rw_it.next()) |line| {
        const p = std.mem.trim(u8, line, "\r \t");
        if (p.len == 0) continue;
        try appendSbplSubpathWithAliases(&buf, p);
    }
    try buf.appendSlice(px.alloc, ")\n");
    try buf.append(px.alloc, 0);
    const owned = try buf.toOwnedSlice(px.alloc);
    return owned[0 .. owned.len - 1 :0];
}

fn macosPreExec(
    ctx: *const px.PreExecContext,
    _: [*:null]const ?[*:0]const u8,
    _: [*:null]const ?[*:0]const u8,
) px.PreExecResult {
    if (ctx.isolation_level == @intFromEnum(common.WlIsolationLevel.l0_restricted_job)) {
        return .{};
    }
    const prof = ctx.sbpl_profile_z orelse return .{
        .status = .appcontainer,
        .detail = "missing Seatbelt SBPL profile",
    };
    var errbuf: ?[*:0]u8 = null;
    if (sandbox_init(prof, 0, &errbuf) != 0) {
        if (errbuf) |eb| sandbox_free_error(eb);
        return .{
            .status = .appcontainer,
            .errno_val = px.lastErrno(),
            .detail = "sandbox_init(SBPL) denied",
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
    var psize = sysctlU32("hw.pagesize");
    if (psize == 0) psize = px.pageSize();

    const translated: u8 = if (sysctlBool("sysctl.proc_translated")) 1 else 0;
    const hv_ok: u8 = if (sysctlBool("kern.hv_support")) 1 else 0;

    var pac_bti: u8 = 0;
    var ext_flags: u8 = 0;
    if (builtin.cpu.arch == .aarch64) {
        const pac = sysctlBool("hw.optional.arm.FEAT_PAuth");
        const bti = sysctlBool("hw.optional.arm.FEAT_BTI");
        if (pac) ext_flags |= common.WL_ARM64_FEAT_PAC;
        if (bti) ext_flags |= common.WL_ARM64_FEAT_BTI;
        if (psize > 4096) ext_flags |= common.WL_ARM64_FEAT_LARGE_PAGES;
        if (pac or bti) pac_bti = 1;
    }

    var tier_mask: u32 = common.WL_TIER_BIT_L0 | common.WL_TIER_BIT_L1 | common.WL_TIER_BIT_L1_5;
    var feat: u64 = common.WL_FEAT_MACOS_SEATBELT;
    if (hv_ok != 0) {
        tier_mask |= common.WL_TIER_BIT_L2;
        feat |= common.WL_FEAT_MACOS_VZ;
    }

    caps.* = .{
        .struct_size = @sizeOf(common.WlHostCapabilities),
        .abi_version = common.abi_version,
        .arch = wl_engine_arch(),
        .os_build_number = parseDarwinRelease(),
        .page_size = psize,
        .tier_support_mask = tier_mask,
        .feature_flags = feat,
        .is_wow64_emulated = translated,
        .cet_shadow_stack_supported = 0,
        .pac_bti_available = pac_bti,
        .hyperv_hcs_available = hv_ok,
        .appcontainer_supported = 1,
        .job_object_iocp_supported = 1,
        .os_kind = @intFromEnum(common.WlOsKind.macos),
        .arm64_ext_flags = ext_flags,
        .landlock_abi = 0,
        .cgroup_v2_available = 0,
        .reserved = @splat(0),
    };
    return @intFromEnum(common.WlStatusCode.ok);
}

pub fn evaluateMacosSpawnPolicy(
    bin: common.WlBinaryInfo,
    host_arch: common.WlArch,
    allow_rosetta_x64: bool,
) struct { status: common.WlStatusCode, emulation: bool, detail: []const u8 } {
    if (bin.format != .macho and bin.format != .macho_universal) {
        return .{ .status = .pe_disallowed_arch, .emulation = false, .detail = "non-Mach-O image rejected on macOS" };
    }
    return switch (host_arch) {
        .arm64 => if (bin.has_arm64)
            .{ .status = .ok, .emulation = false, .detail = "native ARM64 Mach-O verified" }
        else if (bin.has_amd64)
            (if (allow_rosetta_x64)
                .{ .status = .ok, .emulation = true, .detail = "x86_64 Mach-O allowed under Apple Rosetta 2" }
            else
                .{ .status = .prism_blocked, .emulation = true, .detail = "Rosetta 2 x64 emulation blocked by default on macos-arm64" })
        else
            .{ .status = .pe_disallowed_arch, .emulation = false, .detail = "unsupported Mach-O arch on macos-arm64" },
        .x64 => if (bin.has_amd64)
            .{ .status = .ok, .emulation = false, .detail = "native x86_64 Mach-O verified" }
        else
            .{ .status = .pe_disallowed_arch, .emulation = false, .detail = "macos-x64 engine only permits x86_64 Mach-O images" },
        .unknown => .{ .status = .not_supported_arch, .emulation = false, .detail = "unknown host arch" },
    };
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
    const host_arch: common.WlArch = if (builtin.cpu.arch == .aarch64) .arm64 else .x64;
    const eval = evaluateMacosSpawnPolicy(bin_info, host_arch, req.allow_prism_x64 != 0);
    if (eval.status != .ok) {
        res.* = std.mem.zeroes(common.WlSpawnResult);
        res.struct_size = @sizeOf(common.WlSpawnResult);
        res.emulation_detected = if (eval.emulation) 1 else 0;
        common.writeDetail(io, res, eval.detail);
        res.status_code = @intFromEnum(eval.status);
        return res.status_code;
    }

    const ro_slice = if (req.ro_paths_utf8) |p| p[0..req.ro_paths_len] else "";
    const rw_slice = if (req.rw_paths_utf8) |p| p[0..req.rw_paths_len] else "";
    const single_proc = (req.single_process_mode != 0) or (req.isolation_level == @intFromEnum(common.WlIsolationLevel.l1_5_hardened));
    const sbpl_z = buildSeatbeltProfile(exe_slice, ro_slice, rw_slice, single_proc) catch {
        res.* = std.mem.zeroes(common.WlSpawnResult);
        res.struct_size = @sizeOf(common.WlSpawnResult);
        common.writeDetail(io, res, "failed to construct Seatbelt SBPL profile");
        res.status_code = @intFromEnum(common.WlStatusCode.appcontainer);
        return res.status_code;
    };
    defer px.alloc.free(sbpl_z);

    return px.executePosixIsolated(req, io, res, macosPreExec, eval.emulation, sbpl_z.ptr);
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
