const std = @import("std");

pub fn build(b: *std.Build) !void {
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

    const hidapi_dep = b.dependency("hidapi", .{
        .target = target,
        .optimize = optimize,
    });

    const uuid_dep = b.dependency("uuid", .{
        .target = target,
        .optimize = optimize,
    });
    const uuid_module = uuid_dep.module("uuid");

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Module
    // ++++++++++++++++++++++++++++++++++++++++++++

    // Authenticator Module
    // ------------------------------------------------

    const keylib_module = b.addModule("keylib", .{
        .root_source_file = b.path("lib/main.zig"),
        .imports = &.{
            .{ .name = "zbor", .module = zbor_module },
            .{ .name = "uuid", .module = uuid_module },
        },
    });
    try b.modules.put(b.dupe("keylib"), keylib_module);

    const uhid_module = b.addModule("uhid", .{
        .root_source_file = b.path("bindings/linux/src/uhid.zig"),
        .imports = &.{},
    });
    try b.modules.put(b.dupe("uhid"), uhid_module);

    // Re-export zbor module
    try b.modules.put(b.dupe("zbor"), zbor_module);

    // Client Module
    // ------------------------------------------------

    const client_module = b.addModule("clientlib", .{
        .root_source_file = b.path("lib/client.zig"),
        .imports = &.{
            .{ .name = "zbor", .module = zbor_module },
        },
    });
    try b.modules.put(b.dupe("clientlib"), client_module);
    client_module.linkLibrary(hidapi_dep.artifact("hidapi"));

    // Examples
    // ------------------------------------------------

    var client_example = b.addExecutable(.{
        .name = "client",
        .root_source_file = b.path("example/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_example.root_module.addImport("client", client_module);

    const client_example_step = b.step("client-example", "Build the client application example");
    client_example_step.dependOn(&b.addInstallArtifact(client_example, .{}).step);

    var authenticator_example = b.addExecutable(.{
        .name = "authenticator",
        .root_source_file = b.path("example/authenticator.zig"),
        .target = target,
        .optimize = optimize,
    });
    authenticator_example.root_module.addImport("keylib", keylib_module);
    authenticator_example.root_module.addImport("uhid", uhid_module);
    authenticator_example.root_module.addImport("zbor", zbor_dep.module("zbor"));
    authenticator_example.linkLibC();

    const authenticator_example_step = b.step("auth-example", "Build the authenticator example");
    authenticator_example_step.dependOn(&b.addInstallArtifact(authenticator_example, .{}).step);

    // C bindings
    // ------------------------------------------------

    //const c_bindings = b.addStaticLibrary(.{
    //    .name = "keylib",
    //    .root_source_file = .{ .path = "bindings/c/src/keylib.zig" },
    //    .target = target,
    //    .optimize = optimize,
    //});
    //c_bindings.root_module.addImport("keylib", keylib_module);
    //c_bindings.linkLibC();
    //c_bindings.installHeadersDirectory(
    //    b.path("bindings/c/include"),
    //    "keylib",
    //    .{
    //        .exclude_extensions = &.{},
    //        .include_extensions = &.{".h"},
    //    },
    //);
    //b.installArtifact(c_bindings);

    const uhid = b.addStaticLibrary(.{
        .name = "uhid",
        .root_source_file = b.path("bindings/linux/src/uhid-c.zig"),
        .target = target,
        .optimize = optimize,
    });
    uhid.linkLibC();
    uhid.installHeadersDirectory(
        b.path("bindings/linux/include"),
        "keylib",
        .{
            .exclude_extensions = &.{},
            .include_extensions = &.{".h"},
        },
    );
    b.installArtifact(uhid);

    // Python bindings
    // ------------------------------------------------

    // TODO: Figure out how to compile the cython code myself

    //const generate_uhid_bindings = b.addSystemCommand(
    //    &[_][]const u8{ "cython3", "bindings/python/uhidmodule.pyx", "-I", "bindings/linux/include", "-o", "bindings/python/uhidmodule.c", "-3" },
    //);

    //const uhid_py = b.addSharedLibrary(.{
    //    .name = "uhid.linux",
    //    .root_source_file = .{ .path = "bindings/python/uhidmodule.c" },
    //    .target = target,
    //    .optimize = optimize,
    //});
    //uhid_py.step.dependOn(&generate_uhid_bindings.step);
    //uhid_py.linkLibrary(uhid);
    //uhid_py.linkSystemLibrary("python3");
    //uhid_py.linkLibC();
    //b.installArtifact(uhid_py);

    //const build_python_bindings_step = b.step("uhid-py", "Build uhid python bindings");
    //build_python_bindings_step.dependOn(&uhid_py.step);

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Tests
    // ++++++++++++++++++++++++++++++++++++++++++++

    // Creates a step for unit testing.
    const lib_tests = b.addTest(.{
        .root_source_file = b.path("lib/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_tests.root_module.addImport("zbor", zbor_module);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);
}
