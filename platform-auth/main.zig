const std = @import("std");
const fido = @import("fido");
const hid = @import("hid.zig");
const fs = @import("fs.zig");

const uhid = @cImport(
    @cInclude("linux/uhid.h"),
);

const callbacks = @import("callbacks.zig");

fn create(fd: std.fs.File) !void {
    const device_name = "fido2-device";

    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_CREATE2;
    std.mem.copy(u8, event.u.create2.name[0..device_name.len], device_name);
    @memcpy(
        event.u.create2.rd_data[0..hid.ReportDescriptorFidoU2f[0..].len],
        hid.ReportDescriptorFidoU2f[0..],
    );
    event.u.create2.rd_size = hid.ReportDescriptorFidoU2f[0..].len;
    event.u.create2.bus = uhid.BUS_USB;
    event.u.create2.vendor = 0x15d9;
    event.u.create2.product = 0x0a37;
    event.u.create2.version = 0;
    event.u.create2.country = 0;

    try uhid_write(fd, &event);
}

// doesnt work???
fn send_descriptor_string(fd: std.fs.File, s: []const u8) !void {
    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_INPUT2;
    event.u.input2.data[0] = 3;
    @memcpy(event.u.input2.data[1 .. s.len + 1], s);
    event.u.input.size = @as(uhid.u_short, @intCast(s.len)) + 1;

    try uhid_write(fd, &event);
}

fn uhid_write(fd: std.fs.File, event: *uhid.uhid_event) !void {
    fd.writeAll(std.mem.asBytes(event)) catch |e| {
        std.log.err("Error writing to uhid: {}\n", .{e});
        return e;
    };
}

fn destroy(fd: std.fs.File) !void {
    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_DESTROY;
    return uhid_write(fd, &event);
}

pub fn main() !void {
    //const stdin = std.io.getStdIn().reader();
    //const stdout = std.io.getStdOut().writer();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    const pw = callbacks.password("password");
    fs.load("passkey.cks", allocator, pw.?) catch {
        std.log.err("error: unable to open file\n", .{});
        return;
    };

    // 1. Open file
    const path = "/dev/uhid";

    var fd = std.fs.openFileAbsolute(path, .{ .mode = .read_write }) catch {
        std.log.err("Can't open uhid-cdev {s}\n", .{path});
        return;
    };
    defer fd.close();

    // 2. Create uhid device
    try create(fd);
    defer destroy(fd) catch unreachable;

    var authenticator = fido.ctap.authenticator.Authenticator{
        .settings = .{
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            .aaguid = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
            .options = .{
                .rk = true,
                .uv = false,
                // This is a platform authenticator even if we use usb for ipc
                .plat = true,
                // Set clientPin to false if you wanna support a pin and to none
                // if you don't want to use a pin at all.
                .clientPin = false,
                .pinUvAuthToken = true,
                .alwaysUv = true,
            },
            .pinUvAuthProtocols = &.{.V2},
            .transports = &.{.usb},
            .algorithms = &.{.{ .alg = .Es256 }},
            .firmwareVersion = 0xcafe,
            .remainingDiscoverableCredentials = 100,
        },
        .attestation_type = .Self,
        .callbacks = .{
            .rand = std.crypto.random,
            .millis = std.time.milliTimestamp,
            .up = callbacks.up,
            .createEntry = callbacks.createEntry,
            .getEntry = callbacks.getEntry,
            .getEntries = callbacks.getEntries,
            .addEntry = callbacks.addEntry,
            .persist = callbacks.persist,
            .reset = callbacks.reset,
        },
        .algorithms = &.{
            fido.ctap.crypto.algorithms.Es256,
        },
        .token = .{
            //.one = fido.ctap.pinuv.PinUvAuth.v1(callbacks.rand),
            .two = fido.ctap.pinuv.PinUvAuth.v2(std.crypto.random),
        },
        .allocator = allocator,
    };

    if (authenticator.token.one) |*one| {
        one.initialize();
    }
    if (authenticator.token.two) |*two| {
        two.initialize();
    }

    //try authenticator.init();

    while (true) {
        var event = std.mem.zeroes(uhid.uhid_event);
        const l = try fd.read(std.mem.asBytes(&event));
        _ = l;
        //const l = try fd.readAll(packet[0..]);

        switch (event.type) {
            uhid.UHID_START => {
                std.log.info("START\n", .{});
            },
            uhid.UHID_STOP => {
                std.log.info("STOP\n", .{});
            },
            uhid.UHID_OPEN => {
                std.log.info("OPEN\n", .{});
            },
            uhid.UHID_CLOSE => {
                std.log.info("CLOSE\n", .{});
            },
            uhid.UHID_OUTPUT => {
                std.log.info("OUTPUT\n", .{});
                std.log.info("{x}\n", .{std.fmt.fmtSliceHexLower(event.u.output.data[0..64])});

                var response = fido.ctap.transports.ctaphid.authenticator.handle(
                    event.u.output.data[1..event.u.output.size],
                    &authenticator,
                );

                if (response) |*resp| {
                    while (resp.next()) |packet| {
                        var rev = std.mem.zeroes(uhid.uhid_event);
                        rev.type = uhid.UHID_INPUT;
                        @memcpy(rev.u.input.data[0..packet.len], packet);
                        rev.u.input.size = @as(c_ushort, @intCast(packet.len));

                        uhid_write(fd, &rev) catch {
                            std.log.err("failed to send CTAPHID packet\n", .{});
                        };
                    }
                }
            },
            else => {},
        }
    }
}
