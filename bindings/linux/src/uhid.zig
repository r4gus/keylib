const std = @import("std");
const hid = @import("hid.zig");

const uhid = @cImport(
    @cInclude("linux/uhid.h"),
);

const PATH = "/dev/uhid";

export fn uhid_open() c_int {
    var device = std.fs.openFileAbsolute(PATH, .{
        .mode = .read_write,
    }) catch {
        std.log.err("Can't open uhid-cdev {s}\n", .{PATH});
        return -1;
    };
    const flags = std.os.fcntl(device.handle, 3, 0) catch {
        std.log.err("Can't get file stats", .{});
        device.close();
        return -1;
    };
    _ = std.os.fcntl(device.handle, 4, flags | 2048) catch {
        std.log.err("Can't set file to non-blocking", .{});
        device.close();
        return -1;
    };

    create(device) catch {
        std.log.err("Unabel to create CTAPHID device", .{});
        device.close();
        return -1;
    };

    return @intCast(device.handle);
}

export fn uhid_read_packet(fd: c_int, out: [*c]u8) c_int {
    var device = std.fs.File{ .handle = @intCast(fd) };
    var event = std.mem.zeroes(uhid.uhid_event);
    _ = device.read(std.mem.asBytes(&event)) catch {
        return 0;
    };

    if (event.u.output.size < 1) return 0;

    @memcpy(out[0 .. event.u.output.size - 1], event.u.output.data[1..event.u.output.size]);
    return @intCast(event.u.output.size - 1);
}

export fn uhid_write_packet(fd: c_int, in: [*c]u8, len: usize) c_int {
    var device = std.fs.File{ .handle = @intCast(fd) };
    var rev = std.mem.zeroes(uhid.uhid_event);
    rev.type = uhid.UHID_INPUT;
    @memcpy(rev.u.input.data[0..len], in[0..len]);
    rev.u.input.size = @as(c_ushort, @intCast(len));

    uhid_write(device, &rev) catch {
        std.log.err("failed to send CTAPHID packet\n", .{});
        return 0;
    };

    return @intCast(rev.u.input.size);
}

export fn uhid_close(fd: c_int) void {
    var device = std.fs.File{ .handle = @intCast(fd) };
    destroy(device) catch {};
    device.close();
}

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
