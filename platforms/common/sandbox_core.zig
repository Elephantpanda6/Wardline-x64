const std = @import("std");
const common = @import("common.zig");
const w = @import("win32_ffi.zig");

pub const alloc = std.heap.page_allocator;
var acl_mutex: std.atomic.Mutex = .unlocked;

pub fn utf8ToWideZ(bytes: []const u8) ![:0]u16 {
    const wide_len = std.unicode.calcUtf16LeLen(bytes) catch return error.InvalidUtf8;
    const tmp = try alloc.alloc(u16, wide_len + 1);
    errdefer alloc.free(tmp);
    const written = std.unicode.utf8ToUtf16Le(tmp[0..wide_len], bytes) catch return error.InvalidUtf8;
    tmp[written] = 0;
    return tmp[0..written :0];
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

fn envKeyLessThan(_: void, a: []const u8, b: []const u8) bool {
    const a_eq = std.mem.indexOfScalar(u8, a, '=') orelse a.len;
    const b_eq = std.mem.indexOfScalar(u8, b, '=') orelse b.len;
    const ka = a[0..a_eq];
    const kb = b[0..b_eq];
    const n = @min(ka.len, kb.len);
    for (0..n) |i| {
        const ca = std.ascii.toUpper(ka[i]);
        const cb = std.ascii.toUpper(kb[i]);
        if (ca != cb) return ca < cb;
    }
    return ka.len < kb.len;
}

/// Always ensures baseline `SystemRoot` and `PATH`, plus `LOCALAPPDATA` when launching an AppContainer
/// (required by Windows `CreateProcessW` to avoid `ERROR_ENVVAR_NOT_FOUND` 203).
pub fn buildSanitizedEnvBlockW(bytes: []const u8, require_localappdata: bool) ![:0]u16 {
    var entries: std.ArrayList([]const u8) = .empty;
    defer entries.deinit(alloc);

    var has_system_root = false;
    var has_path = false;
    var has_local_appdata = false;

    var it = std.mem.splitScalar(u8, bytes, 0);
    while (it.next()) |entry| {
        if (entry.len == 0) continue;
        const eq_idx = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
        if (eq_idx == 0) continue;
        if (std.mem.indexOfAny(u8, entry, "\r\n") != null) continue;
        if (startsWithIgnoreCase(entry, "SystemRoot=")) has_system_root = true;
        if (startsWithIgnoreCase(entry, "PATH=")) has_path = true;
        if (startsWithIgnoreCase(entry, "LOCALAPPDATA=")) has_local_appdata = true;
        try entries.append(alloc, entry);
    }

    if (!has_system_root) try entries.append(alloc, "SystemRoot=C:\\Windows");
    if (!has_path) try entries.append(alloc, "PATH=C:\\Windows\\System32");
    if (require_localappdata and !has_local_appdata) {
        try entries.append(alloc, "LOCALAPPDATA=C:\\Users\\Default\\AppData\\Local");
    }

    std.mem.sort([]const u8, entries.items, {}, envKeyLessThan);

    var list: std.ArrayList(u16) = .empty;
    errdefer list.deinit(alloc);
    for (entries.items) |entry| {
        const w_entry = try utf8ToWideZ(entry);
        defer alloc.free(w_entry);
        try list.appendSlice(alloc, w_entry);
        try list.append(alloc, 0);
    }
    try list.append(alloc, 0);
    const slice = try list.toOwnedSlice(alloc);
    return slice[0 .. slice.len - 1 :0];
}

pub fn inspectExecutablePeOnDisk(executable_utf8: []const u8) common.WlPeClass {
    const path_w = utf8ToWideZ(executable_utf8) catch return .unknown;
    defer alloc.free(path_w);

    const handle = w.CreateFileW(
        path_w.ptr,
        w.GENERIC_READ,
        w.FILE_SHARE_READ | w.FILE_SHARE_DELETE,
        null,
        w.OPEN_EXISTING,
        w.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (handle == w.INVALID_HANDLE_VALUE) return .unknown;
    defer _ = w.CloseHandle(handle);

    var buf: [4096]u8 = undefined;
    var read_bytes: w.DWORD = 0;
    if (w.ReadFile(handle, &buf, buf.len, &read_bytes, null) == w.FALSE) {
        return .unknown;
    }
    return common.classifyPeBytes(buf[0..read_bytes]);
}

pub fn currentUserSidUtf8() ![]u8 {
    var token: w.HANDLE = undefined;
    if (w.OpenProcessToken(w.GetCurrentProcess(), w.TOKEN_QUERY, &token) == w.FALSE) {
        return error.TokenOpenFailed;
    }
    defer _ = w.CloseHandle(token);

    var needed: w.DWORD = 0;
    _ = w.GetTokenInformation(token, w.TokenUser, null, 0, &needed);
    if (needed == 0) return error.TokenQueryFailed;

    const buf = try alloc.alloc(u8, needed);
    defer alloc.free(buf);
    if (w.GetTokenInformation(token, w.TokenUser, buf.ptr, needed, &needed) == w.FALSE) {
        return error.TokenQueryFailed;
    }

    const token_user: *const w.TOKEN_USER = @ptrCast(@alignCast(buf.ptr));
    var sid_w: w.LPWSTR = undefined;
    if (w.ConvertSidToStringSidW(token_user.User.Sid, &sid_w) == w.FALSE) {
        return error.SidConvertFailed;
    }
    defer _ = w.LocalFree(@ptrCast(sid_w));

    const span = std.mem.span(@as([*:0]const u16, @ptrCast(sid_w)));
    return try std.unicode.utf16LeToUtf8Alloc(alloc, span);
}

fn buildOwnerOnlySecurityDescriptor() !w.PSECURITY_DESCRIPTOR {
    const sid = try currentUserSidUtf8();
    defer alloc.free(sid);

    const sddl_utf8 = try std.fmt.allocPrint(alloc, "D:P(A;OICI;GA;;;{s})(A;OICI;GA;;;SY)", .{sid});
    defer alloc.free(sddl_utf8);
    const sddl_w = try utf8ToWideZ(sddl_utf8);
    defer alloc.free(sddl_w);

    var sd: w.PSECURITY_DESCRIPTOR = null;
    if (w.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_w.ptr, w.SDDL_REVISION_1, &sd, null) == w.FALSE or sd == null) {
        return error.SddlFailed;
    }
    return sd;
}

pub fn createHardenedPipeImpl(name_utf8: []const u8, out_handle: *usize, out_err: *u32) u32 {
    out_err.* = 0;
    const name_w = utf8ToWideZ(name_utf8) catch return @intFromEnum(common.WlStatusCode.invalid_arg);
    defer alloc.free(name_w);

    const sd = buildOwnerOnlySecurityDescriptor() catch {
        out_err.* = w.GetLastError();
        return @intFromEnum(common.WlStatusCode.acl);
    };
    defer _ = w.LocalFree(sd);

    var sa = w.SECURITY_ATTRIBUTES{
        .nLength = @sizeOf(w.SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = sd,
        .bInheritHandle = w.FALSE,
    };

    const pipe = w.CreateNamedPipeW(
        name_w.ptr,
        w.PIPE_ACCESS_DUPLEX | w.FILE_FLAG_FIRST_PIPE_INSTANCE | w.FILE_FLAG_OVERLAPPED,
        w.PIPE_TYPE_BYTE | w.PIPE_READMODE_BYTE | w.PIPE_WAIT | w.PIPE_REJECT_REMOTE_CLIENTS,
        1,
        65536,
        65536,
        0,
        &sa,
    );
    if (pipe == w.INVALID_HANDLE_VALUE) {
        out_err.* = w.GetLastError();
        return @intFromEnum(common.WlStatusCode.pipe);
    }
    out_handle.* = @intFromPtr(pipe);
    return @intFromEnum(common.WlStatusCode.ok);
}

pub fn setOwnerOnlyDaclImpl(path_utf8: []const u8, out_err: *u32) u32 {
    out_err.* = 0;
    const path_w = utf8ToWideZ(path_utf8) catch return @intFromEnum(common.WlStatusCode.invalid_arg);
    defer alloc.free(path_w);

    const sd = buildOwnerOnlySecurityDescriptor() catch {
        out_err.* = w.GetLastError();
        return @intFromEnum(common.WlStatusCode.acl);
    };
    defer _ = w.LocalFree(sd);

    var dacl_present: w.BOOL = w.FALSE;
    var dacl: w.PACL = null;
    var dacl_defaulted: w.BOOL = w.FALSE;
    if (w.GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted) == w.FALSE or dacl_present == w.FALSE) {
        out_err.* = w.GetLastError();
        return @intFromEnum(common.WlStatusCode.acl);
    }

    const res = w.SetNamedSecurityInfoW(
        path_w.ptr,
        w.SE_FILE_OBJECT,
        w.DACL_SECURITY_INFORMATION | w.PROTECTED_DACL_SECURITY_INFORMATION,
        null,
        null,
        dacl,
        null,
    );
    if (res != w.ERROR_SUCCESS) {
        out_err.* = res;
        return @intFromEnum(common.WlStatusCode.acl);
    }
    return @intFromEnum(common.WlStatusCode.ok);
}

pub fn hardenCurrentProcessDaclImpl(out_err: *u32) u32 {
    out_err.* = 0;
    const sd = buildOwnerOnlySecurityDescriptor() catch {
        out_err.* = w.GetLastError();
        return @intFromEnum(common.WlStatusCode.acl);
    };
    defer _ = w.LocalFree(sd);

    var dacl_present: w.BOOL = w.FALSE;
    var dacl: w.PACL = null;
    var dacl_defaulted: w.BOOL = w.FALSE;
    if (w.GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted) == w.FALSE or dacl_present == w.FALSE) {
        out_err.* = w.GetLastError();
        return @intFromEnum(common.WlStatusCode.acl);
    }

    const res = w.SetSecurityInfo(
        w.GetCurrentProcess(),
        w.SE_KERNEL_OBJECT,
        w.DACL_SECURITY_INFORMATION | w.PROTECTED_DACL_SECURITY_INFORMATION,
        null,
        null,
        dacl,
        null,
    );
    if (res != w.ERROR_SUCCESS) {
        out_err.* = res;
        return @intFromEnum(common.WlStatusCode.acl);
    }
    return @intFromEnum(common.WlStatusCode.ok);
}

fn containsIgnoreCaseAscii(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn modifyContainerAces(paths_utf8: []const u8, app_sid: w.PSID, access_mask: w.DWORD, revoke: bool) void {
    while (!acl_mutex.tryLock()) {
        std.atomic.spinLoopHint();
    }
    defer acl_mutex.unlock();

    var it = std.mem.splitScalar(u8, paths_utf8, '\n');
    while (it.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) continue;
        // Skip drive roots and Windows system directories; ALL APPLICATION PACKAGES already has read/execute there.
        if (trimmed.len >= 2 and trimmed.len <= 3 and trimmed[1] == ':') continue;
        if (containsIgnoreCaseAscii(trimmed, "\\windows\\") or std.ascii.endsWithIgnoreCase(trimmed, "\\windows")) continue;

        const path_w = utf8ToWideZ(trimmed) catch continue;
        defer alloc.free(path_w);

        const attrs = w.GetFileAttributesW(path_w.ptr);
        if (attrs == w.INVALID_FILE_ATTRIBUTES or (attrs & w.FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;
        const is_dir = (attrs & w.FILE_ATTRIBUTE_DIRECTORY) != 0;

        var old_dacl: w.PACL = null;
        var old_sd: w.PSECURITY_DESCRIPTOR = null;
        if (w.GetNamedSecurityInfoW(
            path_w.ptr,
            w.SE_FILE_OBJECT,
            w.DACL_SECURITY_INFORMATION,
            null,
            null,
            &old_dacl,
            null,
            &old_sd,
        ) != w.ERROR_SUCCESS) continue;
        defer _ = w.LocalFree(old_sd);

        var ea = w.EXPLICIT_ACCESS_W{
            .grfAccessPermissions = access_mask,
            .grfAccessMode = if (revoke) w.REVOKE_ACCESS else w.SET_ACCESS,
            .grfInheritance = if (is_dir) w.SUB_CONTAINERS_AND_OBJECTS_INHERIT else w.NO_INHERITANCE,
            .Trustee = .{
                .pMultipleTrustee = null,
                .MultipleTrusteeOperation = w.NO_MULTIPLE_TRUSTEE,
                .TrusteeForm = w.TRUSTEE_IS_SID,
                .TrusteeType = w.TRUSTEE_IS_WELL_KNOWN_GROUP,
                .ptstrName = app_sid,
            },
        };
        var new_dacl: w.PACL = null;
        if (w.SetEntriesInAclW(1, &ea, old_dacl, &new_dacl) == w.ERROR_SUCCESS and new_dacl != null) {
            defer _ = w.LocalFree(new_dacl);
            _ = w.SetNamedSecurityInfoW(
                path_w.ptr,
                w.SE_FILE_OBJECT,
                w.DACL_SECURITY_INFORMATION,
                null,
                null,
                new_dacl,
                null,
            );
        }
    }
}

const PipeDrainContext = struct {
    handle: w.HANDLE,
    buf: ?[*]u8,
    cap: usize,
    written: usize,
};

fn pipeDrainThread(ctx: *PipeDrainContext) void {
    var tmp: [4096]u8 = undefined;
    while (true) {
        var n: w.DWORD = 0;
        const ok = w.ReadFile(ctx.handle, &tmp, tmp.len, &n, null);
        if (ok == w.FALSE or n == 0) break;
        if (ctx.buf) |dst| {
            const avail = ctx.cap -| ctx.written;
            const take = @min(avail, @as(usize, n));
            if (take > 0) {
                @memcpy(dst[ctx.written .. ctx.written + take], tmp[0..take]);
                ctx.written += take;
            }
        }
    }
}

fn createLowRestrictedToken() !w.HANDLE {
    var self_token: w.HANDLE = undefined;
    if (w.OpenProcessToken(
        w.GetCurrentProcess(),
        w.TOKEN_DUPLICATE | w.TOKEN_ASSIGN_PRIMARY | w.TOKEN_QUERY | w.TOKEN_ADJUST_DEFAULT | w.TOKEN_ADJUST_PRIVILEGES,
        &self_token,
    ) == w.FALSE) {
        return error.OpenTokenFailed;
    }
    defer _ = w.CloseHandle(self_token);

    var restricted: w.HANDLE = undefined;
    if (w.CreateRestrictedToken(self_token, w.DISABLE_MAX_PRIVILEGE, 0, null, 0, null, 0, null, &restricted) == w.FALSE) {
        return error.RestrictTokenFailed;
    }
    errdefer _ = w.CloseHandle(restricted);

    var sid_buf: [68]u8 align(4) = undefined;
    var sid_size: w.DWORD = sid_buf.len;
    if (w.CreateWellKnownSid(w.WinLowLabelSid, null, &sid_buf, &sid_size) == w.FALSE) {
        return error.LowIntegrityTokenFailed;
    }
    var tml = w.TOKEN_MANDATORY_LABEL{
        .Label = .{
            .Sid = &sid_buf,
            .Attributes = w.SE_GROUP_INTEGRITY | w.SE_GROUP_INTEGRITY_ENABLED,
        },
    };
    if (w.SetTokenInformation(restricted, w.TokenIntegrityLevel, &tml, @sizeOf(w.TOKEN_MANDATORY_LABEL) + sid_size) == w.FALSE) {
        return error.LowIntegrityTokenFailed;
    }

    return restricted;
}

pub fn executeIsolatedChild(
    req: *const common.WlSpawnRequest,
    io: *common.WlIoBuffers,
    res: *common.WlSpawnResult,
    mitigations: [2]u64,
    mitigation_qwords: usize,
    emulation_detected: bool,
    acg_applied: bool,
) u32 {
    res.* = std.mem.zeroes(common.WlSpawnResult);
    res.emulation_detected = if (emulation_detected) 1 else 0;
    res.acg_applied = if (acg_applied) 1 else 0;

    if (req.isolation_level == @intFromEnum(common.WlIsolationLevel.l2_microvm)) {
        common.writeDetail(io, res, "L2 MicroVM isolation requires HCS/WHPX guest runner (probed only in L2 phase)");
        res.status_code = @intFromEnum(common.WlStatusCode.not_supported_arch);
        return res.status_code;
    }

    const exe_slice = if (req.executable_utf8) |p| p[0..req.executable_len] else "";
    const cmd_slice = if (req.cmdline_utf8) |p| p[0..req.cmdline_len] else exe_slice;
    const cwd_slice = if (req.working_dir_utf8) |p| p[0..req.working_dir_len] else "";
    const env_slice = if (req.env_block_utf8) |p| p[0..req.env_block_len] else "";
    const rw_slice = if (req.rw_paths_utf8) |p| p[0..req.rw_paths_len] else "";
    const ro_slice = if (req.ro_paths_utf8) |p| p[0..req.ro_paths_len] else "";
    const ac_name_slice = if (req.container_name_utf8) |p| p[0..req.container_name_len] else "wardline.sandbox.default";

    const use_appcontainer = req.isolation_level == @intFromEnum(common.WlIsolationLevel.l1_appcontainer);
    const exe_w = utf8ToWideZ(exe_slice) catch return failResult(io, res, .invalid_arg, 0, "invalid executable UTF-8");
    defer alloc.free(exe_w);
    const cmd_w = utf8ToWideZ(cmd_slice) catch return failResult(io, res, .invalid_arg, 0, "invalid cmdline UTF-8");
    defer alloc.free(cmd_w);
    const cwd_w: ?[:0]u16 = if (cwd_slice.len > 0) (utf8ToWideZ(cwd_slice) catch return failResult(io, res, .invalid_arg, 0, "invalid working_dir UTF-8")) else null;
    defer if (cwd_w) |c| alloc.free(c);
    const env_w = buildSanitizedEnvBlockW(env_slice, use_appcontainer) catch return failResult(io, res, .invalid_arg, 0, "invalid env UTF-8");
    defer alloc.free(env_w);

    const job = w.CreateJobObjectW(null, null) orelse return failResult(io, res, .job_creation, w.GetLastError(), "CreateJobObjectW failed");
    defer _ = w.CloseHandle(job);

    var ext_lim = std.mem.zeroes(w.JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
    ext_lim.BasicLimitInformation.LimitFlags =
        w.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        w.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if (req.max_processes > 0) {
        ext_lim.BasicLimitInformation.LimitFlags |= w.JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        ext_lim.BasicLimitInformation.ActiveProcessLimit = req.max_processes;
    }
    if (req.max_memory_bytes > 0) {
        ext_lim.BasicLimitInformation.LimitFlags |= w.JOB_OBJECT_LIMIT_JOB_MEMORY;
        ext_lim.JobMemoryLimit = req.max_memory_bytes;
    }
    if (w.SetInformationJobObject(job, w.JobObjectExtendedLimitInformation, &ext_lim, @sizeOf(w.JOBOBJECT_EXTENDED_LIMIT_INFORMATION)) == w.FALSE) {
        return failResult(io, res, .job_creation, w.GetLastError(), "SetInformationJobObject(ExtendedLimit) failed");
    }

    if (req.cpu_rate_percent > 0 and req.cpu_rate_percent <= 100) {
        var cpu_lim = w.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION{
            .ControlFlags = w.JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | w.JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            .CpuRate = req.cpu_rate_percent * 100,
        };
        _ = w.SetInformationJobObject(job, w.JobObjectCpuRateControlInformation, &cpu_lim, @sizeOf(w.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION));
    }

    const iocp = w.CreateIoCompletionPort(w.INVALID_HANDLE_VALUE, null, 0, 1) orelse
        return failResult(io, res, .job_creation, w.GetLastError(), "CreateIoCompletionPort failed");
    defer _ = w.CloseHandle(iocp);

    var assoc = w.JOBOBJECT_ASSOCIATE_COMPLETION_PORT{
        .CompletionKey = job,
        .CompletionPort = iocp,
    };
    if (w.SetInformationJobObject(job, w.JobObjectAssociateCompletionPortInformation, &assoc, @sizeOf(w.JOBOBJECT_ASSOCIATE_COMPLETION_PORT)) == w.FALSE) {
        return failResult(io, res, .job_creation, w.GetLastError(), "JobObjectAssociateCompletionPort failed");
    }

    var pipe_sa = w.SECURITY_ATTRIBUTES{
        .nLength = @sizeOf(w.SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = null,
        .bInheritHandle = w.TRUE,
    };
    var stdout_rd: w.HANDLE = undefined;
    var stdout_wr: w.HANDLE = undefined;
    var stderr_rd: w.HANDLE = undefined;
    var stderr_wr: w.HANDLE = undefined;
    if (w.CreatePipe(&stdout_rd, &stdout_wr, &pipe_sa, 65536) == w.FALSE) {
        return failResult(io, res, .pipe, w.GetLastError(), "CreatePipe(stdout) failed");
    }
    defer _ = w.CloseHandle(stdout_rd);
    var stdout_wr_open = true;
    defer if (stdout_wr_open) {
        _ = w.CloseHandle(stdout_wr);
    };

    if (w.CreatePipe(&stderr_rd, &stderr_wr, &pipe_sa, 65536) == w.FALSE) {
        return failResult(io, res, .pipe, w.GetLastError(), "CreatePipe(stderr) failed");
    }
    defer _ = w.CloseHandle(stderr_rd);
    var stderr_wr_open = true;
    defer if (stderr_wr_open) {
        _ = w.CloseHandle(stderr_wr);
    };

    _ = w.SetHandleInformation(stdout_rd, w.HANDLE_FLAG_INHERIT, 0);
    _ = w.SetHandleInformation(stderr_rd, w.HANDLE_FLAG_INHERIT, 0);

    var app_sid: w.PSID = null;
    var ac_name_w: ?[:0]u16 = null;
    defer if (ac_name_w) |n| alloc.free(n);
    defer if (app_sid != null) {
        if (rw_slice.len > 0) modifyContainerAces(rw_slice, app_sid, 0, true);
        if (ro_slice.len > 0) modifyContainerAces(ro_slice, app_sid, 0, true);
        if (exe_slice.len > 0) {
            modifyContainerAces(exe_slice, app_sid, 0, true);
        }
        _ = w.FreeSid(app_sid);
        if (ac_name_w) |n| {
            _ = w.DeleteAppContainerProfile(n.ptr);
        }
    };

    var sec_caps = std.mem.zeroes(w.SECURITY_CAPABILITIES);
    if (use_appcontainer) {
        const wname = utf8ToWideZ(ac_name_slice) catch return failResult(io, res, .invalid_arg, 0, "invalid container name UTF-8");
        ac_name_w = wname;
        const hr = w.CreateAppContainerProfile(wname.ptr, wname.ptr, wname.ptr, null, 0, &app_sid);
        if (hr < 0) {
            if (w.DeriveAppContainerSidFromAppContainerName(wname.ptr, &app_sid) < 0 or app_sid == null) {
                return failResult(io, res, .appcontainer, @bitCast(hr), "CreateAppContainerProfile failed");
            }
        }
        sec_caps.AppContainerSid = app_sid;
        sec_caps.Capabilities = null;
        sec_caps.CapabilityCount = 0;

        if (exe_slice.len > 0) {
            modifyContainerAces(exe_slice, app_sid, w.GENERIC_READ | w.GENERIC_EXECUTE, false);
        }
        if (ro_slice.len > 0) modifyContainerAces(ro_slice, app_sid, w.GENERIC_READ | w.GENERIC_EXECUTE, false);
        if (rw_slice.len > 0) modifyContainerAces(rw_slice, app_sid, w.GENERIC_READ | w.GENERIC_WRITE | w.GENERIC_EXECUTE, false);
    }

    const attr_count: w.DWORD = if (use_appcontainer) 3 else 2;
    var attr_size: w.SIZE_T = 0;
    _ = w.InitializeProcThreadAttributeList(null, attr_count, 0, &attr_size);
    const attr_mem = alloc.alloc(u8, attr_size) catch return failResult(io, res, .spawn, 0, "attr list alloc failed");
    defer alloc.free(attr_mem);
    if (w.InitializeProcThreadAttributeList(attr_mem.ptr, attr_count, 0, &attr_size) == w.FALSE) {
        return failResult(io, res, .spawn, w.GetLastError(), "InitializeProcThreadAttributeList failed");
    }
    defer w.DeleteProcThreadAttributeList(attr_mem.ptr);

    var handle_list = [2]w.HANDLE{ stdout_wr, stderr_wr };
    if (w.UpdateProcThreadAttribute(
        attr_mem.ptr,
        0,
        w.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        &handle_list,
        @sizeOf([2]w.HANDLE),
        null,
        null,
    ) == w.FALSE) {
        return failResult(io, res, .spawn, w.GetLastError(), "UpdateProcThreadAttribute(HANDLE_LIST) failed");
    }

    var mitigation_buf = mitigations;
    const mitigation_bytes = mitigation_qwords * @sizeOf(u64);
    if (w.UpdateProcThreadAttribute(
        attr_mem.ptr,
        0,
        w.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        &mitigation_buf,
        mitigation_bytes,
        null,
        null,
    ) == w.FALSE) {
        // Retry once with single-QWORD baseline mitigations if OS rejects extended QWORD flags (e.g. CET unsupported).
        var base_only = mitigations[0];
        if (w.UpdateProcThreadAttribute(
            attr_mem.ptr,
            0,
            w.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &base_only,
            @sizeOf(u64),
            null,
            null,
        ) == w.FALSE) {
            return failResult(io, res, .spawn, w.GetLastError(), "UpdateProcThreadAttribute(MITIGATION_POLICY) failed");
        }
    }

    if (use_appcontainer) {
        if (w.UpdateProcThreadAttribute(
            attr_mem.ptr,
            0,
            w.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &sec_caps,
            @sizeOf(w.SECURITY_CAPABILITIES),
            null,
            null,
        ) == w.FALSE) {
            return failResult(io, res, .appcontainer, w.GetLastError(), "UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed");
        }
    }

    // Empty lpDesktop isolates the sandboxed child from WinSta0\Default AND avoids 0xC0000142
    // USER32 DLL init failures when running Low-IL or AppContainer children cleanly.
    var empty_desktop = [1]u16{0};
    var si_ex = w.STARTUPINFOEXW{
        .StartupInfo = .{
            .cb = @sizeOf(w.STARTUPINFOEXW),
            .lpDesktop = @ptrCast(&empty_desktop),
            .dwFlags = 0x00000101,
            .hStdInput = null,
            .hStdOutput = stdout_wr,
            .hStdError = stderr_wr,
        },
        .lpAttributeList = attr_mem.ptr,
    };

    var pi = std.mem.zeroes(w.PROCESS_INFORMATION);
    const creation_flags = w.CREATE_SUSPENDED | w.CREATE_UNICODE_ENVIRONMENT | w.CREATE_NO_WINDOW | w.EXTENDED_STARTUPINFO_PRESENT;

    if (use_appcontainer) {
        if (w.CreateProcessW(
            exe_w.ptr,
            cmd_w.ptr,
            null,
            null,
            w.TRUE,
            creation_flags,
            env_w.ptr,
            if (cwd_w) |c| c.ptr else null,
            &si_ex.StartupInfo,
            &pi,
        ) == w.FALSE) {
            return failResult(io, res, .appcontainer, w.GetLastError(), "CreateProcessW(AppContainer) failed");
        }
    } else {
        const restricted_tok = createLowRestrictedToken() catch {
            return failResult(io, res, .token_restriction, w.GetLastError(), "CreateRestrictedToken failed");
        };
        defer _ = w.CloseHandle(restricted_tok);

        if (w.CreateProcessAsUserW(
            restricted_tok,
            exe_w.ptr,
            cmd_w.ptr,
            null,
            null,
            w.TRUE,
            creation_flags,
            env_w.ptr,
            if (cwd_w) |c| c.ptr else null,
            &si_ex.StartupInfo,
            &pi,
        ) == w.FALSE) {
            return failResult(io, res, .spawn, w.GetLastError(), "CreateProcessAsUserW(RestrictedToken) failed");
        }
    }

    const child_proc = pi.hProcess.?;
    const child_thread = pi.hThread.?;
    defer _ = w.CloseHandle(child_proc);
    defer _ = w.CloseHandle(child_thread);
    res.pid = pi.dwProcessId;

    if (w.AssignProcessToJobObject(job, child_proc) == w.FALSE) {
        const err = w.GetLastError();
        _ = w.TerminateProcess(child_proc, 1);
        return failResult(io, res, .job_creation, err, "AssignProcessToJobObject failed");
    }

    _ = w.CloseHandle(stdout_wr);
    stdout_wr_open = false;
    _ = w.CloseHandle(stderr_wr);
    stderr_wr_open = false;

    var stdout_ctx = PipeDrainContext{
        .handle = stdout_rd,
        .buf = io.stdout_ptr,
        .cap = io.stdout_cap,
        .written = 0,
    };
    var stderr_ctx = PipeDrainContext{
        .handle = stderr_rd,
        .buf = io.stderr_ptr,
        .cap = io.stderr_cap,
        .written = 0,
    };
    const out_thr = std.Thread.spawn(.{}, pipeDrainThread, .{&stdout_ctx}) catch null;
    const err_thr = std.Thread.spawn(.{}, pipeDrainThread, .{&stderr_ctx}) catch null;

    _ = w.ResumeThread(child_thread);

    const timeout_ms: u64 = if (req.timeout_ms == 0) 30_000 else req.timeout_ms;
    const deadline_ms = w.GetTickCount64() + timeout_ms;
    var tree_done = false;
    while (!tree_done) {
        const now_ms = w.GetTickCount64();
        if (now_ms >= deadline_ms) {
            res.timed_out = 1;
            _ = w.TerminateJobObject(job, 0xC000013A);
            break;
        }
        const slice: w.DWORD = @intCast(@min(@as(u64, 50), deadline_ms - now_ms));
        var msg_id: w.DWORD = 0;
        var key: w.ULONG_PTR = 0;
        var ov: ?*anyopaque = null;
        if (w.GetQueuedCompletionStatus(iocp, &msg_id, &key, &ov, slice) != w.FALSE) {
            if (msg_id == w.JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT or msg_id == w.JOB_OBJECT_MSG_JOB_MEMORY_LIMIT) {
                res.oom_killed = 1;
                _ = w.TerminateJobObject(job, 0xC0000017);
                tree_done = true;
            } else if (msg_id == w.JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO) {
                tree_done = true;
            }
        }
    }

    if (out_thr) |t| t.join();
    if (err_thr) |t| t.join();
    res.stdout_len = stdout_ctx.written;
    res.stderr_len = stderr_ctx.written;

    var code: w.DWORD = 1;
    if (w.GetExitCodeProcess(child_proc, &code) != w.FALSE) {
        res.exit_code = code;
    }

    var acct = std.mem.zeroes(w.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION);
    if (w.QueryInformationJobObject(job, w.JobObjectBasicAccountingInformation, &acct, @sizeOf(w.JOBOBJECT_BASIC_ACCOUNTING_INFORMATION), null) != w.FALSE) {
        const hundred_ns: u64 = @intCast(@max(0, acct.TotalUserTime + acct.TotalKernelTime));
        res.cpu_time_us = hundred_ns / 10;
    }
    var final_lim = std.mem.zeroes(w.JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
    if (w.QueryInformationJobObject(job, w.JobObjectExtendedLimitInformation, &final_lim, @sizeOf(w.JOBOBJECT_EXTENDED_LIMIT_INFORMATION), null) != w.FALSE) {
        res.peak_memory_bytes = final_lim.PeakJobMemoryUsed;
    }

    if (res.timed_out != 0) {
        common.writeDetail(io, res, "process tree terminated on timeout");
        res.status_code = @intFromEnum(common.WlStatusCode.timeout_killed);
    } else if (res.oom_killed != 0) {
        common.writeDetail(io, res, "process tree terminated on job memory limit");
        res.status_code = @intFromEnum(common.WlStatusCode.memory_limit);
    } else {
        common.writeDetail(io, res, "completed inside Windows isolation boundary");
        res.status_code = @intFromEnum(common.WlStatusCode.ok);
    }
    return res.status_code;
}

fn failResult(
    io: *common.WlIoBuffers,
    res: *common.WlSpawnResult,
    code: common.WlStatusCode,
    win32_err: u32,
    msg: []const u8,
) u32 {
    res.status_code = @intFromEnum(code);
    res.win32_error = win32_err;
    common.writeDetail(io, res, msg);
    return res.status_code;
}
