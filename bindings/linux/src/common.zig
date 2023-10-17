const std = @import("std");
const hid = @import("hid.zig");

const uhid = @cImport(
    @cInclude("linux/uhid.h"),
);

pub fn create(fd: std.fs.File) !void {
    const device_name = "fido2-device";

    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_CREATE2;
    std.mem.copy(u8, event.u.create2.name[0..device_name.len], device_name);
    @memcpy(
        event.u.create2.rd_data[0..hid.ReportDescriptorFidoU2f[0..].len],
        hid.ReportDescriptorFidoU2f[0..],
    );
    event.u.create2.phys[0] = 'x';
    event.u.create2.uniq[0] = 'y';
    event.u.create2.rd_size = hid.ReportDescriptorFidoU2f[0..].len;
    event.u.create2.bus = uhid.BUS_USB;
    event.u.create2.vendor = 0x15d9;
    event.u.create2.product = 0x0a37;
    event.u.create2.version = 0;
    event.u.create2.country = 0;

    try uhid_write(fd, &event);
}

pub fn uhid_write(fd: std.fs.File, event: *uhid.uhid_event) !void {
    fd.writeAll(std.mem.asBytes(event)) catch |e| {
        std.log.err("Error writing to uhid: {}\n", .{e});
        return e;
    };
}

pub fn destroy(fd: std.fs.File) !void {
    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_DESTROY;
    return uhid_write(fd, &event);
}
