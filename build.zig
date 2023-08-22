const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Dependencies
    // ++++++++++++++++++++++++++++++++++++++++++++

    const zbor_dep = b.dependency("zbor", .{
        .target = target,
        .optimize = optimize,
    });
    const zbor_module = zbor_dep.module("zbor");

    const snorlax_dep = b.dependency("snorlax", .{
        .target = target,
        .optimize = optimize,
    });
    const snorlax_module = snorlax_dep.module("snorlax");

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Module
    // ++++++++++++++++++++++++++++++++++++++++++++

    // Cbor Key Store module
    // ------------------------------------------------

    const cks_module = b.addModule("cks", .{
        .source_file = .{ .path = "cks/main.zig" },
        .dependencies = &.{
            .{ .name = "zbor", .module = zbor_module },
        },
    });

    try b.modules.put(b.dupe("cks"), cks_module);

    // Allocator Module
    // ------------------------------------------------

    const allocator_module = b.addModule("cks", .{
        .source_file = .{ .path = "profiling_allocator/main.zig" },
        .dependencies = &.{
            .{ .name = "profiling_allocator", .module = zbor_module },
        },
    });

    try b.modules.put(b.dupe("profiling_allocator"), allocator_module);

    // Authenticator Module
    // ------------------------------------------------

    const fido_module = b.addModule("fido", .{
        .source_file = .{ .path = "lib/main.zig" },
        .dependencies = &.{
            .{ .name = "zbor", .module = zbor_module },
            .{ .name = "cks", .module = cks_module },
        },
    });

    try b.modules.put(b.dupe("fido"), fido_module);

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Platform Authenticator (linux)
    // ++++++++++++++++++++++++++++++++++++++++++++

    const authenticator = b.addExecutable(.{
        .name = "passkee",
        .root_source_file = .{ .path = "platform-auth/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    authenticator.addModule("fido", fido_module);
    authenticator.addModule("cks", cks_module);
    authenticator.addModule("profiling_allocator", allocator_module);
    authenticator.addModule("snorlax", snorlax_module);
    authenticator.linkSystemLibraryPkgConfigOnly("libnotify");
    authenticator.linkLibC();
    b.installArtifact(authenticator);

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Command Line Tool
    // ++++++++++++++++++++++++++++++++++++++++++++

    //const exe = b.addExecutable(.{
    //    .name = "fido-tool",
    //    .root_source_file = .{ .path = "src/main.zig" },
    //    .target = target,
    //    .optimize = optimize,
    //});

    //exe.addModule("fido", fido_module);
    //exe.addModule("clap", clap_module);
    //exe.linkLibrary(hidapi_dep.artifact("hidapi"));

    //b.installArtifact(exe);
    //const run_cmd = b.addRunArtifact(exe);
    //run_cmd.step.dependOn(b.getInstallStep());

    //// This allows the user to pass arguments to the application in the build
    //// command itself, like this: `zig build run -- arg1 arg2 etc`
    //if (b.args) |args| {
    //    run_cmd.addArgs(args);
    //}

    //const run_step = b.step("run", "Run the app");
    //run_step.dependOn(&run_cmd.step);

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Tests
    // ++++++++++++++++++++++++++++++++++++++++++++

    // Creates a step for unit testing.
    const lib_tests = b.addTest(.{
        .root_source_file = .{ .path = "lib/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib_tests.addModule("zbor", zbor_module);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);

    const cks_tests = b.addTest(.{
        .root_source_file = .{ .path = "cks/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    cks_tests.addModule("zbor", zbor_module);

    const cks_test_step = b.step("test-cks", "Run Cbor Key Store (CKS) library tests");
    cks_test_step.dependOn(&b.addRunArtifact(cks_tests).step);
}
