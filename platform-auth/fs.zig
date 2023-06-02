const std = @import("std");
const cbor = @import("zbor");

pub const Cred = struct {
    id: []u8,
    d: []u8,
};

pub const Data = struct {
    pin_hash: ?[32]u8 = null,
    pin_length: ?u8 = null,
    retries: u8 = 8,
    creds: ?[]Cred = null,

    pub fn load(a: std.mem.Allocator) !Data {
        var dir = std.fs.cwd();

        var file = dir.openFile("fido.db", .{ .mode = .read_write }) catch {
            return @This(){};
        };

        const data = try file.readToEndAlloc(a, 16000);
        defer a.free(data);

        const d = try cbor.parse(@This(), try cbor.DataItem.new(data), .{ .allocator = a });
        return d;
    }

    pub fn writeBack(self: *@This(), a: std.mem.Allocator) !void {
        var dir = std.fs.cwd();

        var file = dir.openFile("fido.db", .{ .mode = .read_write }) catch blk: {
            break :blk try dir.createFile("fido.db", .{});
        };

        var x = std.ArrayList(u8).init(a);
        defer x.deinit();

        try cbor.stringify(self, .{}, x.writer());
        try file.writeAll(x.items);
    }

    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (self.creds) |creds| {
            for (creds) |cred| {
                a.free(cred.id);
                a.free(cred.d);
            }
            a.free(creds);
        }
    }

    pub fn set_pin(self: *@This(), h: [32]u8) void {
        self.pin_hash = h;
    }

    pub fn set_cred(self: *@This(), id: []const u8, d: []const u8, a: std.mem.Allocator) !void {
        const l = if (self.creds == null) 0 else self.creds.?.len;
        var mem = try a.alloc(Cred, l + 1);
        if (self.creds) |creds| {
            std.mem.copy(Cred, mem[0..l], creds[0..]);
        }
        var c = Cred{
            .id = try a.alloc(u8, id.len),
            .d = try a.alloc(u8, d.len),
        };
        std.mem.copy(u8, c.id, id);
        std.mem.copy(u8, c.d, d);
        mem[l] = c;
        if (self.creds) |creds| {
            a.free(creds);
        }
        self.creds = mem;
    }

    pub fn get_cred(self: *const @This(), id: []const u8, a: std.mem.Allocator) ?[]const u8 {
        var d: ?[]const u8 = null;

        if (self.creds) |creds| {
            for (creds) |cred| {
                if (std.mem.eql(u8, cred.id, id)) {
                    var mem = a.alloc(u8, cred.d.len) catch return null;
                    std.mem.copy(u8, mem, cred.d);
                    d = mem;
                }
            }
        }

        return d;
    }
};
