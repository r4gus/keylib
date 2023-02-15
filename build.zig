const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    var zbor_module = b.createModule(.{
        .source_file = .{ .path = "libs/zbor/src/main.zig" },
    });

    const lib = b.addStaticLibrary(.{
        .name = "fido",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.addModule("zbor", zbor_module);

    // This declares intent for the library to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    lib.install();

    // Creates a step for unit testing.
    const lib_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib_tests.addModule("zbor", zbor_module);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&lib_tests.step);
}
