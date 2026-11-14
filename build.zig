const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const x64_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = .msvc,
    });

    const common_x64 = b.createModule(.{
        .root_source_file = b.path("platforms/common/common.zig"),
        .target = x64_target,
        .optimize = optimize,
    });
    common_x64.link_libc = true;
    common_x64.addIncludePath(b.path("platforms/common"));

    const engine_x64_mod = b.createModule(.{
        .root_source_file = b.path("platforms/win-x64/engine_x64.zig"),
        .target = x64_target,
        .optimize = optimize,
    });
    engine_x64_mod.link_libc = true;
    engine_x64_mod.addImport("common", common_x64);
    engine_x64_mod.addIncludePath(b.path("platforms/common"));

    const lib_x64 = b.addLibrary(.{
        .linkage = .static,
        .name = "wardline_engine_x64",
        .root_module = engine_x64_mod,
    });
    b.installArtifact(lib_x64);

    const test_common = b.addTest(.{
        .name = "common-tests",
        .root_module = common_x64,
    });
    const run_common_tests = b.addRunArtifact(test_common);

    const test_x64 = b.addTest(.{
        .name = "win-x64-tests",
        .root_module = engine_x64_mod,
    });
    const run_x64_tests = b.addRunArtifact(test_x64);

    const test_step = b.step("test", "Run native Windows x64 Zig unit tests");
    test_step.dependOn(&run_common_tests.step);
    test_step.dependOn(&run_x64_tests.step);
}
