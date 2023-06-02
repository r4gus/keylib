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

    const hidapi_dep = b.dependency("hidapi", .{
        .target = target,
        .optimize = optimize,
    });
    _ = hidapi_dep;

    const clap_dep = b.dependency("clap", .{
        .target = target,
        .optimize = optimize,
    });
    const clap_module = clap_dep.module("clap");
    _ = clap_module;

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Module
    // ++++++++++++++++++++++++++++++++++++++++++++

    // Authenticator Module
    // ------------------------------------------------

    const fido_module = b.addModule("fido", .{
        .source_file = .{ .path = "lib/main.zig" },
        .dependencies = &.{
            .{ .name = "zbor", .module = zbor_module },
        },
    });

    try b.modules.put(b.dupe("fido"), fido_module);

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Platform Authenticator (linux)
    // ++++++++++++++++++++++++++++++++++++++++++++

    const LINUX_DIR = "platform-auth/linux/";

    const install_udev_rule = b.addSystemCommand(&[_][]const u8{
        "sudo", "cp", LINUX_DIR ++ "70-fido-access.rules", "/etc/udev/rules.d/",
    });

    const reload_rules = b.addSystemCommand(&[_][]const u8{
        "sudo", "udevadm", "control", "--reload-rules",
    });
    reload_rules.step.dependOn(&install_udev_rule.step);

    const trigger_rules = b.addSystemCommand(&[_][]const u8{
        "sudo", "udevadm", "trigger",
    });
    trigger_rules.step.dependOn(&reload_rules.step);

    const install_udev_rule_step = b.step("install-rule", "Install udev rule for usb gadget");
    install_udev_rule_step.dependOn(&trigger_rules.step);

    const install_usb_gadget = b.addSystemCommand(&[_][]const u8{
        "sudo", "make", "-C", LINUX_DIR, "install",
    });

    const install_usb_gadget_step = b.step("install-gadget", "Install usb gadget required for platform authenticator");
    install_usb_gadget_step.dependOn(&install_usb_gadget.step);

    const uninstall_usb_gadget = b.addSystemCommand(&[_][]const u8{
        "sudo", "make", "-C", LINUX_DIR, "uninstall",
    });

    const uninstall_usb_gadget_step = b.step("uninstall-gadget", "Uninstall usb gadget");
    uninstall_usb_gadget_step.dependOn(&uninstall_usb_gadget.step);

    const authenticator = b.addExecutable(.{
        .name = "platauth",
        .root_source_file = .{ .path = "platform-auth/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    authenticator.addModule("fido", fido_module);
    authenticator.addModule("zbor", zbor_module);
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
}
