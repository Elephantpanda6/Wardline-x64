const std = @import("std");
const builtin = @import("builtin");
const common = @import("common");
const px = common.posix;
const linux = std.os.linux;
const c = std.c;

const AT_HWCAP: c_ulong = 16;
const AT_HWCAP2: c_ulong = 26;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const LL_EXEC: u64 = 1 << 0;
const LL_WRITE_FILE: u64 = 1 << 1;
const LL_READ_FILE: u64 = 1 << 2;
const LL_READ_DIR: u64 = 1 << 3;
const LL_REMOVE_DIR: u64 = 1 << 4;
const LL_REMOVE_FILE: u64 = 1 << 5;
const LL_MAKE_CHAR: u64 = 1 << 6;
const LL_MAKE_DIR: u64 = 1 << 7;
const LL_MAKE_REG: u64 = 1 << 8;
const LL_MAKE_SOCK: u64 = 1 << 9;
const LL_MAKE_FIFO: u64 = 1 << 10;
const LL_MAKE_BLOCK: u64 = 1 << 11;
const LL_MAKE_SYM: u64 = 1 << 12;
const LL_REFER: u64 = 1 << 13;
const LL_TRUNCATE: u64 = 1 << 14;

const RulesetAttr = extern struct {
    handled_access_fs: u64,
};

const PathBeneathAttr = extern struct {
    allowed_access: u64 align(1),
    parent_fd: i32 align(1),
};

const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

fn bpfStmt(code: u16, k: u32) SockFilter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

fn bpfJump(code: u16, k: u32, jt: u8, jf: u8) SockFilter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

fn sysNum(comptime s: linux.SYS) u32 {
    return @intCast(@intFromEnum(s));
}

fn parseKernelVersionNumber() u32 {
    var flags: c.O = .{};
    flags.ACCMODE = .RDONLY;
    flags.CLOEXEC = true;
    const fd = c.open("/proc/sys/kernel/osrelease", flags);
    if (fd < 0) return 0;
    defer _ = c.close(fd);

    var buf: [64]u8 = undefined;
    const n = c.read(fd, &buf, buf.len);
    if (n <= 0) return 0;
    const raw = std.mem.trim(u8, buf[0..@intCast(n)], " \r\n\t");
    var it = std.mem.tokenizeAny(u8, raw, ".-+");
    const maj = std.fmt.parseInt(u32, it.next() orelse "0", 10) catch 0;
    const min = std.fmt.parseInt(u32, it.next() orelse "0", 10) catch 0;
    const pat = std.fmt.parseInt(u32, it.next() orelse "0", 10) catch 0;
    return maj * 10000 + min * 100 + pat;
}

fn probeLandlockAbi() c_int {
    const rc = linux.syscall3(.landlock_create_ruleset, 0, 0, LANDLOCK_CREATE_RULESET_VERSION);
    const signed: isize = @bitCast(rc);
    if (signed < 0) return -1;
    return @intCast(signed);
}

fn probeUsernsEnabled() bool {
    var flags: c.O = .{};
    flags.ACCMODE = .RDONLY;
    flags.CLOEXEC = true;
    const fd = c.open("/proc/sys/kernel/unprivileged_userns_clone", flags);
    if (fd < 0) return true; // Vanilla kernels without Debian/Ubuntu sysctl allow userns by default.
    defer _ = c.close(fd);
    var b: [4]u8 = undefined;
    const n = c.read(fd, &b, b.len);
    if (n <= 0) return true;
    return b[0] != '0';
}

fn probeX64CetCpuinfo() u8 {
    var flags: c.O = .{};
    flags.ACCMODE = .RDONLY;
    flags.CLOEXEC = true;
    const fd = c.open("/proc/cpuinfo", flags);
    if (fd < 0) return 0;
    defer _ = c.close(fd);
    var buf: [4096]u8 = undefined;
    const n = c.read(fd, &buf, buf.len);
    if (n <= 0) return 0;
    const txt = buf[0..@intCast(n)];
    if (std.mem.indexOf(u8, txt, "user_shstk") != null or std.mem.indexOf(u8, txt, "shstk") != null) {
        return 1;
    }
    return 0;
}

fn writeProcFile(path: [*:0]const u8, data: []const u8) bool {
    var flags: c.O = .{};
    flags.ACCMODE = .WRONLY;
    flags.CLOEXEC = true;
    const fd = c.open(path, flags);
    if (fd < 0) return false;
    defer _ = c.close(fd);
    var off: usize = 0;
    while (off < data.len) {
        const n = c.write(fd, data[off..].ptr, data.len - off);
        if (n <= 0) return false;
        off += @intCast(n);
    }
    return true;
}

fn setupUserNamespace(uid: u32, gid: u32) px.PreExecResult {
    const flags: usize = linux.CLONE.NEWUSER | linux.CLONE.NEWNET | linux.CLONE.NEWIPC | linux.CLONE.NEWUTS;
    const rc = linux.syscall1(.unshare, flags);
    const s: isize = @bitCast(rc);
    if (s < 0) {
        return .{
            .status = .appcontainer,
            .errno_val = @intCast(-s),
            .detail = "unshare(CLONE_NEWUSER|CLONE_NEWNET) failed",
        };
    }

    _ = writeProcFile("/proc/self/setgroups", "deny");

    var ubuf: [64]u8 = undefined;
    const uline = std.fmt.bufPrint(&ubuf, "0 {d} 1\n", .{uid}) catch return .{
        .status = .appcontainer,
        .detail = "uid_map format error",
    };
    if (!writeProcFile("/proc/self/uid_map", uline)) {
        return .{
            .status = .appcontainer,
            .errno_val = px.lastErrno(),
            .detail = "failed writing /proc/self/uid_map",
        };
    }

    var gbuf: [64]u8 = undefined;
    const gline = std.fmt.bufPrint(&gbuf, "0 {d} 1\n", .{gid}) catch return .{
        .status = .appcontainer,
        .detail = "gid_map format error",
    };
    if (!writeProcFile("/proc/self/gid_map", gline)) {
        return .{
            .status = .appcontainer,
            .errno_val = px.lastErrno(),
            .detail = "failed writing /proc/self/gid_map",
        };
    }

    return .{};
}

fn addLandlockPathRule(rs_fd: c_int, path_z: [*:0]const u8, dir_access: u64, file_access: u64) void {
    var open_flags: linux.O = .{};
    open_flags.PATH = true;
    open_flags.CLOEXEC = true;
    const rc_open = linux.open(path_z, open_flags, 0);
    const s_open: isize = @bitCast(rc_open);
    if (s_open < 0) return;
    const pfd: i32 = @intCast(s_open);
    defer _ = c.close(pfd);

    var sx = std.mem.zeroes(linux.Statx);
    const AT_EMPTY_PATH: u32 = 0x1000;
    const rc_st = linux.statx(pfd, "", AT_EMPTY_PATH, .{ .TYPE = true }, &sx);
    const s_st: isize = @bitCast(rc_st);
    const is_dir = (s_st == 0) and ((sx.mode & 0o170000) == 0o040000);

    const attr = PathBeneathAttr{
        .allowed_access = if (is_dir) dir_access else file_access,
        .parent_fd = pfd,
    };
    if (attr.allowed_access == 0) return;
    _ = linux.syscall4(
        .landlock_add_rule,
        @as(usize, @intCast(rs_fd)),
        LANDLOCK_RULE_PATH_BENEATH,
        @intFromPtr(&attr),
        0,
    );
}

fn applyLandlock(ctx: *const px.PreExecContext) px.PreExecResult {
    const abi = probeLandlockAbi();
    if (abi < 1) return .{}; // Graceful on pre-5.13 kernels without Landlock.

    var handled: u64 = LL_EXEC | LL_WRITE_FILE | LL_READ_FILE | LL_READ_DIR | LL_REMOVE_DIR |
        LL_REMOVE_FILE | LL_MAKE_CHAR | LL_MAKE_DIR | LL_MAKE_REG | LL_MAKE_SOCK |
        LL_MAKE_FIFO | LL_MAKE_BLOCK | LL_MAKE_SYM;
    if (abi >= 2) handled |= LL_REFER;
    if (abi >= 3) handled |= LL_TRUNCATE;

    const attr = RulesetAttr{ .handled_access_fs = handled };
    const rc_rs = linux.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), @sizeOf(RulesetAttr), 0);
    const s_rs: isize = @bitCast(rc_rs);
    if (s_rs < 0) {
        return .{
            .status = .appcontainer,
            .errno_val = @intCast(-s_rs),
            .detail = "landlock_create_ruleset failed",
        };
    }
    const rs_fd: c_int = @intCast(s_rs);
    defer _ = c.close(rs_fd);

    const ro_dir = (LL_READ_FILE | LL_READ_DIR | LL_EXEC) & handled;
    const ro_file = (LL_READ_FILE | LL_EXEC) & handled;
    const rw_dir = handled;
    const rw_file = (LL_READ_FILE | LL_WRITE_FILE | LL_EXEC | LL_TRUNCATE) & handled;

    const sys_ro_paths = [_][*:0]const u8{
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/lib32",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
        "/etc/localtime",
        "/proc/self",
        "/dev/urandom",
        "/dev/zero",
    };
    for (sys_ro_paths) |sp| {
        addLandlockPathRule(rs_fd, sp, ro_dir, ro_file);
    }
    addLandlockPathRule(rs_fd, "/dev/null", ro_dir, rw_file);
    addLandlockPathRule(rs_fd, ctx.exe_path_z, ro_dir, ro_file);
    if (ctx.exe_dir_z) |ed| {
        addLandlockPathRule(rs_fd, ed, ro_dir, ro_file);
    }
    for (ctx.ro_paths) |p| {
        addLandlockPathRule(rs_fd, p, ro_dir, ro_file);
    }
    for (ctx.rw_paths) |p| {
        addLandlockPathRule(rs_fd, p, rw_dir, rw_file);
    }

    const rc_rest = linux.syscall2(.landlock_restrict_self, @as(usize, @intCast(rs_fd)), 0);
    const s_rest: isize = @bitCast(rc_rest);
    if (s_rest < 0) {
        return .{
            .status = .appcontainer,
            .errno_val = @intCast(-s_rest),
            .detail = "landlock_restrict_self failed",
        };
    }
    return .{};
}

fn applySeccomp() px.PreExecResult {
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    const arch_const: u32 = if (builtin.cpu.arch == .aarch64)
        0xC000_00B7
    else
        0xC000_003E;

    const off_arch: u32 = @offsetOf(linux.SECCOMP.data, "arch");
    const off_nr: u32 = @offsetOf(linux.SECCOMP.data, "nr");
    const off_arg0: u32 = @offsetOf(linux.SECCOMP.data, "arg0");

    const ret_kill: u32 = linux.SECCOMP.RET.KILL_PROCESS;
    const ret_allow: u32 = linux.SECCOMP.RET.ALLOW;
    const ret_eacces: u32 = linux.SECCOMP.RET.ERRNO | 13;
    const ret_eperm: u32 = linux.SECCOMP.RET.ERRNO | 1;

    const filter = [_]SockFilter{
        // 0: load arch
        bpfStmt(BPF_LD | BPF_W | BPF_ABS, off_arch),
        // 1: if arch == native -> skip kill (jump +1)
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, arch_const, 1, 0),
        // 2: kill foreign arch
        bpfStmt(BPF_RET | BPF_K, ret_kill),
        // 3: load nr
        bpfStmt(BPF_LD | BPF_W | BPF_ABS, off_nr),
        // 4: check dangerous syscalls -> jump to EPERM (idx 21, diff from 4..14 is 16..6)
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.ptrace), 16, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.process_vm_readv), 15, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.process_vm_writev), 14, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.mount), 13, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.umount2), 12, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.kexec_load), 11, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.init_module), 10, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.finit_module), 9, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.bpf), 8, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.io_uring_setup), 7, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.keyctl), 6, 0),
        // 15: check socket -> if not socket jump to ALLOW (idx 22, jf = 6)
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, sysNum(.socket), 0, 6),
        // 16: load socket arg0 (domain)
        bpfStmt(BPF_LD | BPF_W | BPF_ABS, off_arg0),
        // 17..20: block AF_INET(2), AF_INET6(10), AF_NETLINK(16), AF_PACKET(17)
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, 2, 5, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, 10, 4, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, 16, 3, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, 17, 2, 1),
        // 21: EPERM
        bpfStmt(BPF_RET | BPF_K, ret_eperm),
        // 22: ALLOW
        bpfStmt(BPF_RET | BPF_K, ret_allow),
        // 23: EACCES
        bpfStmt(BPF_RET | BPF_K, ret_eacces),
    };

    const prog = SockFprog{
        .len = filter.len,
        .filter = &filter,
    };
    const rc = linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &prog);
    const s: isize = @bitCast(rc);
    if (s < 0) {
        return .{
            .status = .appcontainer,
            .errno_val = @intCast(-s),
            .detail = "seccomp(SET_MODE_FILTER) failed",
        };
    }
    return .{};
}

fn linuxPreExec(
    ctx: *const px.PreExecContext,
    _: [*:null]const ?[*:0]const u8,
    _: [*:null]const ?[*:0]const u8,
) px.PreExecResult {
    const PR_SET_DUMPABLE: usize = 4;
    const PR_SET_NO_NEW_PRIVS: usize = 38;
    _ = linux.prctl(@intCast(PR_SET_DUMPABLE), 0, 0, 0, 0);

    if (ctx.isolation_level == @intFromEnum(common.WlIsolationLevel.l0_restricted_job)) {
        const rc_nnp = linux.prctl(@intCast(PR_SET_NO_NEW_PRIVS), 1, 0, 0, 0);
        const s_nnp: isize = @bitCast(rc_nnp);
        if (s_nnp < 0) {
            return .{
                .status = .token_restriction,
                .errno_val = @intCast(-s_nnp),
                .detail = "PR_SET_NO_NEW_PRIVS failed",
            };
        }
        return .{};
    }

    // L1: UserNS + NetNS + NO_NEW_PRIVS + Landlock + Seccomp
    const ns_res = setupUserNamespace(ctx.parent_uid, ctx.parent_gid);
    if (ns_res.status != .ok) return ns_res;

    const rc_nnp = linux.prctl(@intCast(PR_SET_NO_NEW_PRIVS), 1, 0, 0, 0);
    const s_nnp: isize = @bitCast(rc_nnp);
    if (s_nnp < 0) {
        return .{
            .status = .appcontainer,
            .errno_val = @intCast(-s_nnp),
            .detail = "PR_SET_NO_NEW_PRIVS failed",
        };
    }

    const ll_res = applyLandlock(ctx);
    if (ll_res.status != .ok) return ll_res;

    const sc_res = applySeccomp();
    if (sc_res.status != .ok) return sc_res;

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
    const caps = out_caps orelse return @intFromEnum(common.WlStatusCode.invalid_arg);
    const psize = px.pageSize();
    const kvm_ok: u8 = if (c.access("/dev/kvm", 0) == 0) 1 else 0;
    const ll_abi = probeLandlockAbi();
    const userns_ok = probeUsernsEnabled();

    var pac_bti: u8 = 0;
    var cet: u8 = 0;
    var ext_flags: u8 = 0;

    if (builtin.cpu.arch == .aarch64) {
        const hwcap = c.getauxval(AT_HWCAP);
        const hwcap2 = c.getauxval(AT_HWCAP2);
        const pac_on = (hwcap & ((@as(c_ulong, 1) << 30) | (@as(c_ulong, 1) << 31))) != 0;
        const sve_on = (hwcap & (@as(c_ulong, 1) << 22)) != 0;
        const bti_on = (hwcap2 & (@as(c_ulong, 1) << 17)) != 0;
        const mte_on = (hwcap2 & (@as(c_ulong, 1) << 18)) != 0;
        const sve2_on = (hwcap2 & (@as(c_ulong, 1) << 1)) != 0;
        if (pac_on) ext_flags |= common.WL_ARM64_FEAT_PAC;
        if (bti_on) ext_flags |= common.WL_ARM64_FEAT_BTI;
        if (mte_on) ext_flags |= common.WL_ARM64_FEAT_MTE;
        if (sve_on) ext_flags |= common.WL_ARM64_FEAT_SVE;
        if (sve2_on) ext_flags |= common.WL_ARM64_FEAT_SVE2;
        if (psize > 4096) ext_flags |= common.WL_ARM64_FEAT_LARGE_PAGES;
        if (pac_on or bti_on) pac_bti = 1;
    } else {
        cet = probeX64CetCpuinfo();
    }

    caps.* = .{
        .arch = wl_engine_arch(),
        .abi_version = common.abi_version,
        .is_wow64_emulated = 0,
        .cet_shadow_stack_supported = cet,
        .pac_bti_available = pac_bti,
        .hyperv_hcs_available = kvm_ok,
        .appcontainer_supported = if (userns_ok and ll_abi >= 0) 1 else if (userns_ok) 1 else 0,
        .job_object_iocp_supported = 1,
        .os_kind = @intFromEnum(common.WlOsKind.linux),
        .arm64_ext_flags = ext_flags,
        .os_build_number = parseKernelVersionNumber(),
        .page_size = psize,
    };
    return @intFromEnum(common.WlStatusCode.ok);
}

pub fn evaluateLinuxSpawnPolicy(
    bin: common.WlBinaryInfo,
    host_arch: common.WlArch,
    allow_emulated_x64: bool,
) struct { status: common.WlStatusCode, emulation: bool, detail: []const u8 } {
    if (bin.format != .elf) {
        return .{ .status = .pe_disallowed_arch, .emulation = false, .detail = "non-ELF image rejected on Linux" };
    }
    return switch (host_arch) {
        .arm64 => switch (bin.arch) {
            .arm64 => .{ .status = .ok, .emulation = false, .detail = "native AArch64 ELF verified" },
            .amd64 => if (allow_emulated_x64)
                .{ .status = .ok, .emulation = true, .detail = "x86_64 ELF allowed under Linux emulation" }
            else
                .{ .status = .prism_blocked, .emulation = true, .detail = "x86_64 ELF blocked by default on linux-arm64" },
            else => .{ .status = .pe_disallowed_arch, .emulation = false, .detail = "unsupported ELF machine on linux-arm64" },
        },
        .x64 => switch (bin.arch) {
            .amd64 => .{ .status = .ok, .emulation = false, .detail = "native x86_64 ELF verified" },
            else => .{ .status = .pe_disallowed_arch, .emulation = false, .detail = "linux-x64 engine only permits native x86_64 ELF images" },
        },
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

    const exe_slice = if (req.executable_utf8) |p| p[0..req.executable_len] else "";
    const bin_info = px.inspectExecutableOnDisk(exe_slice);
    const host_arch: common.WlArch = if (builtin.cpu.arch == .aarch64) .arm64 else .x64;
    const eval = evaluateLinuxSpawnPolicy(bin_info, host_arch, req.allow_prism_x64 != 0);
    if (eval.status != .ok) {
        res.* = std.mem.zeroes(common.WlSpawnResult);
        res.emulation_detected = if (eval.emulation) 1 else 0;
        common.writeDetail(io, res, eval.detail);
        res.status_code = @intFromEnum(eval.status);
        return res.status_code;
    }

    return px.executePosixIsolated(req, io, res, linuxPreExec, eval.emulation, null);
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
