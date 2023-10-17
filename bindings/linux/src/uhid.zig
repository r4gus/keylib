const std = @import("std");
const hid = @import("hid.zig");
const common = @import("common.zig");

const uhid = @cImport(
    @cInclude("linux/uhid.h"),
);

const PATH = "/dev/uhid";

const create = common.create;
const uhid_write = common.uhid_write;
const destroy = common.destroy;

pub const Uhid = struct {
    device: std.fs.File,

    pub fn open() !@This() {
        var device = std.fs.openFileAbsolute(PATH, .{
            .mode = .read_write,
        }) catch |e| {
            std.log.err("Can't open uhid-cdev {s}\n", .{PATH});
            return e;
        };

        const flags = std.os.fcntl(device.handle, 3, 0) catch |e| {
            std.log.err("Can't get file stats", .{});
            device.close();
            return e;
        };
        _ = std.os.fcntl(device.handle, 4, flags | 2048) catch |e| {
            std.log.err("Can't set file to non-blocking", .{});
            device.close();
            return e;
        };

        create(device) catch |e| {
            std.log.err("Unabel to create CTAPHID device", .{});
            device.close();
            return e;
        };

        return .{
            .device = device,
        };
    }

    pub fn close(self: *const @This()) void {
        destroy(self.device) catch {
            std.log.err("Unabel to destroy UHID device", .{});
        };
        self.device.close();
    }

    pub fn read(self: *const @This(), out: *[64]u8) ?[]u8 {
        var event = std.mem.zeroes(uhid.uhid_event);
        _ = self.device.read(std.mem.asBytes(&event)) catch {
            return 0;
        };

        if (event.u.output.size < 1) return null;

        @memcpy(out[0 .. event.u.output.size - 1], event.u.output.data[1..event.u.output.size]);
        return out[0 .. event.u.output.size - 1];
    }

    pub fn write(self: *const @This(), in: []const u8) !void {
        if (in.len > 64) return error.InvalidSizedPacket;

        var rev = std.mem.zeroes(uhid.uhid_event);
        rev.type = uhid.UHID_INPUT;
        @memcpy(rev.u.input.data[0..in.len], in[0..]);

        uhid_write(self.device, &rev) catch |e| {
            std.log.err("failed to send CTAPHID packet\n", .{});
            return e;
        };
    }
};
