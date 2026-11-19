const std = @import("std");
const builtin = @import("builtin");
const common = @import("common.zig");
const c = std.c;

pub const alloc = std.heap.page_allocator;

pub const PreExecContext = struct {
    isolation_level: u32,
    ro_paths: []const [*:0]const u8,
    rw_paths: []const [*:0]const u8,
    exe_path_z: [*:0]const u8,
    exe_dir_z: ?[*:0]const u8,
    parent_uid: u32,
    parent_gid: u32,
    sbpl_profile_z: ?[*:0]const u8,
};

pub const PreExecResult = struct {
    status: common.WlStatusCode = .ok,
    errno_val: u32 = 0,
    detail: []const u8 = "",
};

pub const PreExecFn = *const fn (
    ctx: *const PreExecContext,
    argv_ptrs: [*:null]const ?[*:0]const u8,
    envp_ptrs: [*:null]const ?[*:0]const u8,
) PreExecResult;

const ChildErrPacket = extern struct {
    status_code: u32,
    errno_val: u32,
    msg_len: u32,
    msg: [128]u8,
};

pub fn lastErrno() u32 {
    const val = c._errno().*;
    return if (val < 0) 0 else @intCast(val);
}

pub fn dupeZ(bytes: []const u8) ![:0]u8 {
    const buf = try alloc.alloc(u8, bytes.len + 1);
    @memcpy(buf[0..bytes.len], bytes);
    buf[bytes.len] = 0;
    return buf[0..bytes.len :0];
}

pub fn pageSize() u32 {
    const sc_pagesize: c_int = @intFromEnum(c._SC.PAGESIZE);
    const sz = c.sysconf(sc_pagesize);
    if (sz <= 0) return 4096;
    return @intCast(sz);
}

pub fn inspectExecutableOnDisk(path_utf8: []const u8) common.WlBinaryInfo {
    const empty = common.WlBinaryInfo{
        .format = .unknown,
        .arch = .unknown,
        .has_arm64 = false,
        .has_amd64 = false,
    };
    const path_z = dupeZ(path_utf8) catch return empty;
    defer alloc.free(path_z);

    var flags: c.O = .{};
    flags.ACCMODE = .RDONLY;
    flags.CLOEXEC = true;
    // Note: Do not set O_NOFOLLOW here because distro binaries (e.g. /bin/echo, /usr/bin/id)
    // are frequently legitimate symlinks into /usr/lib or alternatives directories.
    const fd = c.open(path_z.ptr, flags);
    if (fd < 0) return empty;
    defer _ = c.close(fd);

    var buf: [4096]u8 = undefined;
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = c.read(fd, buf[filled..].ptr, buf.len - filled);
        if (n < 0) {
            if (lastErrno() == @intFromEnum(c.E.INTR)) continue;
            break;
        }
        if (n == 0) break;
        filled += @intCast(n);
    }
    if (filled == 0) return empty;
    return common.classifyBinaryBytes(buf[0..filled]);
}

pub fn setOwnerOnlyMode(path_utf8: []const u8, is_dir: bool, out_err: *u32) u32 {
    const path_z = dupeZ(path_utf8) catch {
        out_err.* = 12;
        return @intFromEnum(common.WlStatusCode.acl);
    };
    defer alloc.free(path_z);

    const mode: c.mode_t = if (is_dir) 0o700 else 0o600;
    if (c.chmod(path_z.ptr, mode) != 0) {
        out_err.* = lastErrno();
        return @intFromEnum(common.WlStatusCode.acl);
    }
    out_err.* = 0;
    return @intFromEnum(common.WlStatusCode.ok);
}

pub fn hardenProcessCommon(out_err: *u32) u32 {
    const zero_core = c.rlimit{
        .cur = 0,
        .max = 0,
    };
    if (c.setrlimit(.CORE, &zero_core) != 0) {
        out_err.* = lastErrno();
        return @intFromEnum(common.WlStatusCode.acl);
    }
    if (builtin.os.tag == .linux) {
        const PR_SET_DUMPABLE: c_int = 4;
        if (c.prctl(PR_SET_DUMPABLE, @as(usize, 0), @as(usize, 0), @as(usize, 0), @as(usize, 0)) != 0) {
            out_err.* = lastErrno();
            return @intFromEnum(common.WlStatusCode.acl);
        }
    }
    out_err.* = 0;
    return @intFromEnum(common.WlStatusCode.ok);
}

fn monotonicMs() u64 {
    var ts: c.timespec = undefined;
    if (c.clock_gettime(.MONOTONIC, &ts) != 0) return 0;
    const sec: u64 = if (ts.sec < 0) 0 else @intCast(ts.sec);
    const nsec: u64 = if (ts.nsec < 0) 0 else @intCast(ts.nsec);
    return sec *| 1000 +| (nsec / 1_000_000);
}

fn setCloexec(fd: c.fd_t) void {
    const FD_CLOEXEC: c_int = 1;
    _ = c.fcntl(fd, c.F.SETFD, FD_CLOEXEC);
}

fn setNonBlocking(fd: c.fd_t) void {
    const flags = c.fcntl(fd, c.F.GETFL, @as(c_int, 0));
    if (flags >= 0) {
        var o_nb: c.O = @bitCast(@as(c_int, flags));
        o_nb.NONBLOCK = true;
        const raw: c_int = @bitCast(o_nb);
        _ = c.fcntl(fd, c.F.SETFL, raw);
    }
}

fn closeFdIfOpen(fd: c.fd_t) void {
    if (fd >= 0) {
        _ = c.close(fd);
    }
}

fn writeFullFd(fd: c.fd_t, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = c.write(fd, bytes[off..].ptr, bytes.len - off);
        if (n <= 0) break;
        off += @intCast(n);
    }
}

fn sendChildError(fd: c.fd_t, status: common.WlStatusCode, errno_val: u32, detail: []const u8) void {
    var pkt = ChildErrPacket{
        .status_code = @intFromEnum(status),
        .errno_val = errno_val,
        .msg_len = @intCast(@min(detail.len, 128)),
        .msg = @splat(0),
    };
    @memcpy(pkt.msg[0..pkt.msg_len], detail[0..pkt.msg_len]);
    writeFullFd(fd, std.mem.asBytes(&pkt));
}

fn buildArgv(exe_z: [:0]const u8, cmdline: []const u8) !struct {
    owned: std.ArrayList([:0]u8),
    ptrs: std.ArrayList(?[*:0]const u8),
} {
    var owned: std.ArrayList([:0]u8) = .empty;
    errdefer {
        for (owned.items) |s| alloc.free(s);
        owned.deinit(alloc);
    }
    var ptrs: std.ArrayList(?[*:0]const u8) = .empty;
    errdefer ptrs.deinit(alloc);

    if (cmdline.len == 0) {
        try ptrs.append(alloc, exe_z.ptr);
    } else if (std.mem.indexOfScalar(u8, cmdline, 0) != null) {
        var it = std.mem.splitScalar(u8, cmdline, 0);
        while (it.next()) |part| {
            const z = try dupeZ(part);
            try owned.append(alloc, z);
            try ptrs.append(alloc, z.ptr);
        }
    } else {
        // Fallback for simple non-NUL command strings.
        var it = std.mem.tokenizeAny(u8, cmdline, " \t");
        var count: usize = 0;
        while (it.next()) |raw| {
            const tok = std.mem.trim(u8, raw, "\"");
            if (tok.len == 0) continue;
            const z = try dupeZ(tok);
            try owned.append(alloc, z);
            try ptrs.append(alloc, z.ptr);
            count += 1;
        }
        if (count == 0) {
            try ptrs.append(alloc, exe_z.ptr);
        }
    }
    try ptrs.append(alloc, null);
    return .{ .owned = owned, .ptrs = ptrs };
}

fn buildEnvp(env_block: []const u8) !struct {
    owned: std.ArrayList([:0]u8),
    ptrs: std.ArrayList(?[*:0]const u8),
} {
    var owned: std.ArrayList([:0]u8) = .empty;
    errdefer {
        for (owned.items) |s| alloc.free(s);
        owned.deinit(alloc);
    }
    var ptrs: std.ArrayList(?[*:0]const u8) = .empty;
    errdefer ptrs.deinit(alloc);

    var has_path = false;
    var it = std.mem.splitScalar(u8, env_block, 0);
    while (it.next()) |entry| {
        if (entry.len == 0) continue;
        if (std.mem.indexOfScalar(u8, entry, '=') == null) continue;
        if (entry.len >= 5 and std.ascii.eqlIgnoreCase(entry[0..5], "PATH=")) {
            has_path = true;
        }
        const z = try dupeZ(entry);
        try owned.append(alloc, z);
        try ptrs.append(alloc, z.ptr);
    }
    if (!has_path) {
        const default_path = try dupeZ("PATH=/usr/bin:/bin");
        try owned.append(alloc, default_path);
        try ptrs.append(alloc, default_path.ptr);
    }
    try ptrs.append(alloc, null);
    return .{ .owned = owned, .ptrs = ptrs };
}

fn splitNewlinePaths(raw: []const u8) !std.ArrayList([:0]u8) {
    var list: std.ArrayList([:0]u8) = .empty;
    errdefer {
        for (list.items) |s| alloc.free(s);
        list.deinit(alloc);
    }
    var it = std.mem.splitScalar(u8, raw, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, "\r \t");
        if (trimmed.len == 0) continue;
        const z = try dupeZ(trimmed);
        try list.append(alloc, z);
    }
    return list;
}

fn dirNameZ(path: []const u8) !?[:0]u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        if (idx == 0) return try dupeZ("/");
        return try dupeZ(path[0..idx]);
    }
    return null;
}

fn applyChildRlimits(req: *const common.WlSpawnRequest) void {
    const zero_core = c.rlimit{ .cur = 0, .max = 0 };
    _ = c.setrlimit(.CORE, &zero_core);

    const nofile_lim = c.rlimit{ .cur = 256, .max = 256 };
    _ = c.setrlimit(.NOFILE, &nofile_lim);

    const stack_bytes: c.rlim_t = 2 * 1024 * 1024;
    var cur_stack: c.rlimit = undefined;
    if (c.getrlimit(.STACK, &cur_stack) == 0) {
        if (cur_stack.cur > stack_bytes) {
            const new_stack = c.rlimit{
                .cur = stack_bytes,
                .max = @min(cur_stack.max, stack_bytes),
            };
            _ = c.setrlimit(.STACK, &new_stack);
        }
    }

    if (req.timeout_ms > 0) {
        const secs: c.rlim_t = @intCast((@as(u64, req.timeout_ms) + 999) / 1000 + 2);
        const cpu_lim = c.rlimit{ .cur = secs, .max = secs };
        _ = c.setrlimit(.CPU, &cpu_lim);
    }

    if (req.max_memory_bytes > 0) {
        const cap_u64 = req.max_memory_bytes;
        const as_val: c.rlim_t = @intCast(@min(cap_u64, @as(u64, std.math.maxInt(i64))));
        const as_lim = c.rlimit{ .cur = as_val, .max = as_val };
        _ = c.setrlimit(.AS, &as_lim);
    }
}

fn closeExtraFds(keep_err_fd: c.fd_t) void {
    var fd: c.fd_t = 3;
    while (fd < 1024) : (fd += 1) {
        if (fd != keep_err_fd) {
            _ = c.close(fd);
        }
    }
}

fn drainFd(fd: c.fd_t, dst_ptr: ?[*]u8, dst_cap: usize, written: *usize) bool {
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = c.read(fd, &tmp, tmp.len);
        if (n < 0) {
            const err = lastErrno();
            if (err == @intFromEnum(c.E.INTR)) continue;
            if (err == @intFromEnum(c.E.AGAIN)) return false;
            return true;
        }
        if (n == 0) return true;
        const got: usize = @intCast(n);
        if (dst_ptr) |p| {
            if (written.* < dst_cap) {
                const space = dst_cap - written.*;
                const copy_n = @min(space, got);
                @memcpy(p[written.* .. written.* + copy_n], tmp[0..copy_n]);
                written.* += copy_n;
            }
        }
    }
}

pub fn executePosixIsolated(
    req: *const common.WlSpawnRequest,
    io: *common.WlIoBuffers,
    res: *common.WlSpawnResult,
    pre_exec: PreExecFn,
    emulation_detected: bool,
    sbpl_profile_z: ?[*:0]const u8,
) u32 {
    res.* = std.mem.zeroes(common.WlSpawnResult);
    res.struct_size = @sizeOf(common.WlSpawnResult);
    res.emulation_detected = if (emulation_detected) 1 else 0;
    res.acg_applied = 0;

    if (req.isolation_level == @intFromEnum(common.WlIsolationLevel.l2_microvm)) {
        res.status_code = @intFromEnum(common.WlStatusCode.not_supported_arch);
        common.writeDetail(io, res, "L2 MicroVM backend not attached on this host");
        return res.status_code;
    }

    const exe_slice = if (req.executable_utf8) |p| p[0..req.executable_len] else "";
    if (exe_slice.len == 0) {
        res.status_code = @intFromEnum(common.WlStatusCode.invalid_arg);
        common.writeDetail(io, res, "empty executable path");
        return res.status_code;
    }

    const exe_z = dupeZ(exe_slice) catch {
        res.status_code = @intFromEnum(common.WlStatusCode.spawn);
        common.writeDetail(io, res, "out of memory duplicating executable path");
        return res.status_code;
    };
    defer alloc.free(exe_z);

    const exe_dir = dirNameZ(exe_slice) catch null;
    defer if (exe_dir) |d| alloc.free(d);

    const wd_slice = if (req.working_dir_utf8) |p| p[0..req.working_dir_len] else "";
    const wd_z: ?[:0]u8 = if (wd_slice.len > 0) dupeZ(wd_slice) catch null else null;
    defer if (wd_z) |w| alloc.free(w);

    const cmd_slice = if (req.cmdline_utf8) |p| p[0..req.cmdline_len] else "";
    var argv = buildArgv(exe_z, cmd_slice) catch {
        res.status_code = @intFromEnum(common.WlStatusCode.spawn);
        common.writeDetail(io, res, "failed to allocate argv");
        return res.status_code;
    };
    defer {
        for (argv.owned.items) |s| alloc.free(s);
        argv.owned.deinit(alloc);
        argv.ptrs.deinit(alloc);
    }

    const env_slice = if (req.env_block_utf8) |p| p[0..req.env_block_len] else "";
    var envp = buildEnvp(env_slice) catch {
        res.status_code = @intFromEnum(common.WlStatusCode.spawn);
        common.writeDetail(io, res, "failed to allocate envp");
        return res.status_code;
    };
    defer {
        for (envp.owned.items) |s| alloc.free(s);
        envp.owned.deinit(alloc);
        envp.ptrs.deinit(alloc);
    }

    const ro_slice = if (req.ro_paths_utf8) |p| p[0..req.ro_paths_len] else "";
    var ro_owned = splitNewlinePaths(ro_slice) catch {
        res.status_code = @intFromEnum(common.WlStatusCode.spawn);
        return res.status_code;
    };
    defer {
        for (ro_owned.items) |s| alloc.free(s);
        ro_owned.deinit(alloc);
    }
    var ro_ptrs: std.ArrayList([*:0]const u8) = .empty;
    defer ro_ptrs.deinit(alloc);
    for (ro_owned.items) |s| ro_ptrs.append(alloc, s.ptr) catch {};

    const rw_slice = if (req.rw_paths_utf8) |p| p[0..req.rw_paths_len] else "";
    var rw_owned = splitNewlinePaths(rw_slice) catch {
        res.status_code = @intFromEnum(common.WlStatusCode.spawn);
        return res.status_code;
    };
    defer {
        for (rw_owned.items) |s| alloc.free(s);
        rw_owned.deinit(alloc);
    }
    var rw_ptrs: std.ArrayList([*:0]const u8) = .empty;
    defer rw_ptrs.deinit(alloc);
    for (rw_owned.items) |s| rw_ptrs.append(alloc, s.ptr) catch {};

    var out_pipe: [2]c.fd_t = .{ -1, -1 };
    var err_pipe: [2]c.fd_t = .{ -1, -1 };
    var exec_err_pipe: [2]c.fd_t = .{ -1, -1 };
    if (c.pipe(&out_pipe) != 0 or c.pipe(&err_pipe) != 0 or c.pipe(&exec_err_pipe) != 0) {
        closeFdIfOpen(out_pipe[0]);
        closeFdIfOpen(out_pipe[1]);
        closeFdIfOpen(err_pipe[0]);
        closeFdIfOpen(err_pipe[1]);
        closeFdIfOpen(exec_err_pipe[0]);
        closeFdIfOpen(exec_err_pipe[1]);
        res.status_code = @intFromEnum(common.WlStatusCode.pipe);
        res.win32_error = lastErrno();
        common.writeDetail(io, res, "pipe() failed");
        return res.status_code;
    }
    setCloexec(exec_err_pipe[0]);
    setCloexec(exec_err_pipe[1]);

    const pre_ctx = PreExecContext{
        .isolation_level = req.isolation_level,
        .ro_paths = ro_ptrs.items,
        .rw_paths = rw_ptrs.items,
        .exe_path_z = exe_z.ptr,
        .exe_dir_z = if (exe_dir) |d| d.ptr else null,
        .parent_uid = c.geteuid(),
        .parent_gid = c.getegid(),
        .sbpl_profile_z = sbpl_profile_z,
    };

    const argv_c: [*:null]const ?[*:0]const u8 = @ptrCast(argv.ptrs.items.ptr);
    const envp_c: [*:null]const ?[*:0]const u8 = @ptrCast(envp.ptrs.items.ptr);

    const pid = c.fork();
    if (pid < 0) {
        res.status_code = @intFromEnum(common.WlStatusCode.spawn);
        res.win32_error = lastErrno();
        closeFdIfOpen(out_pipe[0]);
        closeFdIfOpen(out_pipe[1]);
        closeFdIfOpen(err_pipe[0]);
        closeFdIfOpen(err_pipe[1]);
        closeFdIfOpen(exec_err_pipe[0]);
        closeFdIfOpen(exec_err_pipe[1]);
        common.writeDetail(io, res, "fork() failed");
        return res.status_code;
    }

    if (pid == 0) {
        // Child: strictly async-signal-safe calls only.
        _ = c.close(out_pipe[0]);
        _ = c.close(err_pipe[0]);
        _ = c.close(exec_err_pipe[0]);

        _ = c.setsid();

        var dev_null_flags: c.O = .{};
        dev_null_flags.ACCMODE = .RDWR;
        const null_fd = c.open("/dev/null", dev_null_flags);
        if (null_fd >= 0) {
            _ = c.dup2(null_fd, 0);
            if (null_fd > 2) _ = c.close(null_fd);
        } else {
            _ = c.close(0);
        }
        _ = c.dup2(out_pipe[1], 1);
        _ = c.dup2(err_pipe[1], 2);
        if (out_pipe[1] > 2) _ = c.close(out_pipe[1]);
        if (err_pipe[1] > 2) _ = c.close(err_pipe[1]);

        closeExtraFds(exec_err_pipe[1]);

        if (wd_z) |wd| {
            if (c.chdir(wd.ptr) != 0) {
                sendChildError(exec_err_pipe[1], .spawn, lastErrno(), "chdir() to working_dir failed");
                c._exit(126);
            }
        }

        applyChildRlimits(req);

        const hook_res = pre_exec(&pre_ctx, argv_c, envp_c);
        if (hook_res.status != .ok) {
            sendChildError(exec_err_pipe[1], hook_res.status, hook_res.errno_val, hook_res.detail);
            c._exit(126);
        }

        _ = c.execve(exe_z.ptr, argv_c, envp_c);
        sendChildError(exec_err_pipe[1], .spawn, lastErrno(), "execve() failed");
        c._exit(127);
    }

    // Parent
    _ = c.close(out_pipe[1]);
    _ = c.close(err_pipe[1]);
    _ = c.close(exec_err_pipe[1]);

    res.pid = @intCast(pid);
    setNonBlocking(out_pipe[0]);
    setNonBlocking(err_pipe[0]);
    setNonBlocking(exec_err_pipe[0]);

    const timeout_ms: u64 = if (req.timeout_ms == 0) 30_000 else req.timeout_ms;
    const deadline_ms = monotonicMs() +| timeout_ms;

    var out_closed = false;
    var err_closed = false;
    var exec_closed = false;
    var err_pkt_bytes: [@sizeOf(ChildErrPacket)]u8 align(@alignOf(ChildErrPacket)) = undefined;
    var err_pkt_len: usize = 0;

    while (!out_closed or !err_closed or !exec_closed) {
        const now = monotonicMs();
        if (now >= deadline_ms) {
            res.timed_out = 1;
            _ = c.kill(-pid, c.SIG.KILL);
            _ = c.kill(pid, c.SIG.KILL);
            break;
        }

        var pfds: [3]c.pollfd = undefined;
        var nfds: usize = 0;
        var idx_out: ?usize = null;
        var idx_err: ?usize = null;
        var idx_exec: ?usize = null;

        if (!out_closed) {
            idx_out = nfds;
            pfds[nfds] = .{ .fd = out_pipe[0], .events = c.POLL.IN, .revents = 0 };
            nfds += 1;
        }
        if (!err_closed) {
            idx_err = nfds;
            pfds[nfds] = .{ .fd = err_pipe[0], .events = c.POLL.IN, .revents = 0 };
            nfds += 1;
        }
        if (!exec_closed) {
            idx_exec = nfds;
            pfds[nfds] = .{ .fd = exec_err_pipe[0], .events = c.POLL.IN, .revents = 0 };
            nfds += 1;
        }

        const wait_ms: c_int = @intCast(@min(@as(u64, 50), deadline_ms - now));
        const prc = c.poll(&pfds, @intCast(nfds), wait_ms);
        if (prc < 0) {
            if (lastErrno() == @intFromEnum(c.E.INTR)) continue;
            break;
        }

        if (idx_out) |i| {
            if (pfds[i].revents != 0) {
                if (drainFd(out_pipe[0], io.stdout_ptr, io.stdout_cap, &res.stdout_len)) {
                    out_closed = true;
                }
            }
        }
        if (idx_err) |i| {
            if (pfds[i].revents != 0) {
                if (drainFd(err_pipe[0], io.stderr_ptr, io.stderr_cap, &res.stderr_len)) {
                    err_closed = true;
                }
            }
        }
        if (idx_exec) |i| {
            if (pfds[i].revents != 0) {
                while (true) {
                    const rem = err_pkt_bytes.len - err_pkt_len;
                    if (rem == 0) {
                        var sink: [64]u8 = undefined;
                        const extra = c.read(exec_err_pipe[0], &sink, sink.len);
                        if (extra <= 0) {
                            if (extra == 0 or lastErrno() != @intFromEnum(c.E.AGAIN)) exec_closed = true;
                            break;
                        }
                    } else {
                        const n = c.read(exec_err_pipe[0], err_pkt_bytes[err_pkt_len..].ptr, rem);
                        if (n < 0) {
                            const e = lastErrno();
                            if (e == @intFromEnum(c.E.INTR)) continue;
                            if (e != @intFromEnum(c.E.AGAIN)) exec_closed = true;
                            break;
                        }
                        if (n == 0) {
                            exec_closed = true;
                            break;
                        }
                        err_pkt_len += @intCast(n);
                    }
                }
            }
        }
    }

    _ = c.close(out_pipe[0]);
    _ = c.close(err_pipe[0]);
    _ = c.close(exec_err_pipe[0]);

    var wstatus: c_int = 0;
    var ru = std.mem.zeroes(c.rusage);
    while (true) {
        const w = c.wait4(pid, &wstatus, 0, &ru);
        if (w < 0) {
            if (lastErrno() == @intFromEnum(c.E.INTR)) continue;
            break;
        }
        break;
    }

    const u_status: u32 = @bitCast(wstatus);
    if (c.W.IFEXITED(u_status)) {
        res.exit_code = c.W.EXITSTATUS(u_status);
    } else if (c.W.IFSIGNALED(u_status)) {
        const sig: u32 = @intCast(@intFromEnum(c.W.TERMSIG(u_status)));
        res.exit_code = 128 + sig;
    } else {
        res.exit_code = 1;
    }

    const maxrss: u64 = if (ru.maxrss < 0) 0 else @intCast(ru.maxrss);
    res.peak_memory_bytes = if (builtin.os.tag == .macos) maxrss else maxrss *| 1024;

    const u_sec: u64 = if (ru.utime.sec < 0) 0 else @intCast(ru.utime.sec);
    const u_usec: u64 = if (ru.utime.usec < 0) 0 else @intCast(ru.utime.usec);
    const s_sec: u64 = if (ru.stime.sec < 0) 0 else @intCast(ru.stime.sec);
    const s_usec: u64 = if (ru.stime.usec < 0) 0 else @intCast(ru.stime.usec);
    res.cpu_time_us = (u_sec +| s_sec) *| 1_000_000 +| u_usec +| s_usec;

    if (err_pkt_len >= @sizeOf(ChildErrPacket)) {
        const pkt: *const ChildErrPacket = @ptrCast(@alignCast(&err_pkt_bytes));
        res.status_code = pkt.status_code;
        res.win32_error = pkt.errno_val;
        const mlen = @min(@as(usize, pkt.msg_len), pkt.msg.len);
        common.writeDetail(io, res, pkt.msg[0..mlen]);
        return res.status_code;
    }

    if (res.timed_out != 0) {
        common.writeDetail(io, res, "process group terminated on timeout");
        res.status_code = @intFromEnum(common.WlStatusCode.timeout_killed);
        return res.status_code;
    }

    if (req.max_memory_bytes > 0 and c.W.IFSIGNALED(u_status)) {
        const sig = c.W.TERMSIG(u_status);
        if (sig == .ABRT or sig == .SEGV or sig == .KILL) {
            res.oom_killed = 1;
        }
    }
    if (req.max_memory_bytes > 0 and res.peak_memory_bytes > req.max_memory_bytes) {
        res.oom_killed = 1;
    }

    common.writeDetail(io, res, "completed inside POSIX isolation boundary");
    res.status_code = @intFromEnum(common.WlStatusCode.ok);
    return res.status_code;
}
