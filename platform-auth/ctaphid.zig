const std = @import("std");

pub const Usb = struct {
    f: std.fs.File,
    buffer: [64]u8 = undefined,

    pub fn open(path: []const u8) !@This() {
        return @This(){
            .f = try std.fs.openFileAbsolute(path, .{ .mode = .read_write }),
        };
    }

    pub fn read(self: *@This()) ![]const u8 {
        const l = try self.f.readAll(self.buffer[0..]);
        return self.buffer[0..l];
    }

    pub fn write(self: *@This(), bytes: []const u8) !void {
        try self.f.writeAll(bytes);
    }
};
