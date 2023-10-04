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

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Module
    // ++++++++++++++++++++++++++++++++++++++++++++

    // Authenticator Module
    // ------------------------------------------------

    const keylib_module = b.addModule("keylib", .{
        .source_file = .{ .path = "lib/main.zig" },
        .dependencies = &.{
            .{ .name = "zbor", .module = zbor_module },
        },
    });
    try b.modules.put(b.dupe("keylib"), keylib_module);

    // C libs
    // ------------------------------------------------

    const c_bindings = b.addStaticLibrary(.{
        .name = "keylib",
        .root_source_file = .{ .path = "bindings/c/src/keylib.zig" },
        .target = target,
        .optimize = optimize,
    });
    c_bindings.addModule("keylib", keylib_module);
    c_bindings.linkLibC();
    c_bindings.installHeadersDirectoryOptions(.{
        .source_dir = std.Build.LazyPath{ .path = "bindings/c/include" },
        .install_dir = .header,
        .install_subdir = "keylib",
        .exclude_extensions = &.{".c"},
    });
    b.installArtifact(c_bindings);

    const uhid = b.addStaticLibrary(.{
        .name = "uhid",
        .root_source_file = .{ .path = "bindings/linux/src/uhid.zig" },
        .target = target,
        .optimize = optimize,
    });
    uhid.linkLibC();
    uhid.installHeadersDirectoryOptions(.{
        .source_dir = std.Build.LazyPath{ .path = "bindings/linux/include" },
        .install_dir = .header,
        .install_subdir = "keylib",
        .exclude_extensions = &.{".c"},
    });
    b.installArtifact(uhid);

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
}
