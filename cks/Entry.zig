const std = @import("std");
const cbor = @import("zbor");
const Extension = @import("Extension.zig");

/// Id of the given entry
id: []const u8,

/// Times specific to this entry
times: @import("Times.zig"),

/// List of key-value pairs that allow the storage of additional fields
/// not covered by this struct.
fields: ?[]Extension = null,

allocator: std.mem.Allocator,

pub fn cborStringify(self: *const @This(), options: cbor.StringifyOptions, out: anytype) !void {
    _ = options;

    try cbor.stringify(self, .{
        .from_cborStringify = true,
        .field_settings = &.{
            .{ .name = "allocator", .options = .{ .skip = true } },
        },
    }, out);
}

pub fn new(id: []const u8, time: i64, allocator: std.mem.Allocator) @This() {
    return @This(){
        .id = id,
        .times = .{
            .lastModificationTime = time,
            .creationTime = time,
            .lastAccessTime = time,
            .usageCount = 0,
        },
        .fields = null,
        .allocator = allocator,
    };
}

pub fn deinit(self: *const @This()) void {
    self.allocator.free(self.id);
    if (self.fields) |fields| {
        for (fields) |field| {
            self.allocator.free(field.key);
            self.allocator.free(field.value);
        }
        self.allocator.free(fields);
    }
}

pub fn addField(self: *@This(), field: Extension, time: i64) !void {
    self.fields = if (self.fields) |fields| blk: {
        for (fields) |_field| {
            if (std.mem.eql(u8, _field.key, field.key)) {
                return error.DoesExist;
            }
        }

        var new_mem = try self.allocator.alloc(Extension, fields.len + 1);
        @memcpy(new_mem[0..fields.len], fields);
        self.allocator.free(fields);
        break :blk new_mem;
    } else blk: {
        break :blk try self.allocator.alloc(Extension, 1);
    };
    // At this point self.fields is NOT null

    var k = try self.allocator.alloc(u8, field.key.len);
    errdefer self.allocator.free(k);
    var v = try self.allocator.alloc(u8, field.value.len);
    errdefer self.allocator.free(v);
    @memcpy(k, field.key);
    @memcpy(v, field.value);

    self.fields.?[self.fields.?.len - 1] = .{ .key = k, .value = v };
    self.times.lastModificationTime = time;
}

pub fn getField(self: *@This(), key: []const u8, time: i64) ?[]const u8 {
    if (self.fields) |fields| {
        self.times.lastAccessTime = time;
        for (fields) |field| {
            if (std.mem.eql(u8, field.key, key)) {
                return field.value;
            }
        }
    }
    return null;
}

pub fn updateField(self: *@This(), key: []const u8, value: []const u8, time: i64) !void {
    if (self.fields) |fields| {
        for (fields) |*field| {
            if (std.mem.eql(u8, field.key, key)) {
                var mem = try self.allocator.alloc(u8, value.len);
                @memcpy(mem, value);
                const k = field.key;
                self.allocator.free(field.value);
                field.* = .{ .key = k, .value = mem };

                self.times.lastModificationTime = time;
                return;
            }
        }
    }
    return error.DoesNotExist;
}

pub fn removeField(self: *@This(), key: []const u8, time: i64) !?Extension {
    if (self.fields) |fields| {
        var i: usize = 0;
        for (fields) |field| {
            if (std.mem.eql(u8, key, field.key)) {
                var new_mem = try self.allocator.alloc(Extension, fields.len - 1);
                @memcpy(new_mem[0..i], fields[0..i]);
                @memcpy(new_mem[i..], fields[i + 1 ..]);
                self.fields = new_mem;
                self.allocator.free(fields);
                self.times.lastModificationTime = time;
                return field;
            }

            i += 1;
        }
    }
    return null;
}

test "create Entry with UserName and URL fields" {
    const allocator = std.testing.allocator;
    const time = std.time.milliTimestamp();
    var id = try allocator.alloc(u8, 64);
    std.crypto.random.bytes(id[0..]);

    var e = @This().new(id, time, allocator);
    defer e.deinit();

    try std.testing.expectEqualSlices(u8, id[0..], e.id[0..]);
    try std.testing.expectEqual(time, e.times.lastModificationTime);
    try std.testing.expectEqual(time, e.times.creationTime);
    try std.testing.expectEqual(time, e.times.lastAccessTime);
    try std.testing.expectEqual(e.times.usageCount, 0);

    const time2 = std.time.milliTimestamp();
    try e.addField(.{ .key = "UserName", .value = "r4gus" }, time2);
    try std.testing.expectEqual(time2, e.times.lastModificationTime);
    try std.testing.expectEqual(time, e.times.creationTime);
    try std.testing.expectEqual(time, e.times.lastAccessTime);
    try std.testing.expectEqual(e.times.usageCount, 0);
    try std.testing.expectEqual(@as(usize, @intCast(1)), e.fields.?.len);

    const time3 = std.time.milliTimestamp();
    try std.testing.expectEqualSlices(u8, "r4gus", e.getField("UserName", time3).?);
    try std.testing.expectEqual(time2, e.times.lastModificationTime);
    try std.testing.expectEqual(time, e.times.creationTime);
    try std.testing.expectEqual(time3, e.times.lastAccessTime);
    try std.testing.expectEqual(e.times.usageCount, 0);
    try std.testing.expectEqual(@as(usize, @intCast(1)), e.fields.?.len);

    const time4 = std.time.milliTimestamp();
    try e.addField(.{ .key = "URL", .value = "https://ziglang.org" }, time4);
    try std.testing.expectEqual(time4, e.times.lastModificationTime);
    try std.testing.expectEqual(time, e.times.creationTime);
    try std.testing.expectEqual(time3, e.times.lastAccessTime);
    try std.testing.expectEqual(e.times.usageCount, 0);
    try std.testing.expectEqual(@as(usize, @intCast(2)), e.fields.?.len);

    const time5 = std.time.milliTimestamp();
    try std.testing.expectEqualSlices(u8, "r4gus", e.getField("UserName", time5).?);
    try std.testing.expectEqualSlices(u8, "https://ziglang.org", e.getField("URL", time5).?);
    try std.testing.expectEqual(time4, e.times.lastModificationTime);
    try std.testing.expectEqual(time, e.times.creationTime);
    try std.testing.expectEqual(time5, e.times.lastAccessTime);

    const time6 = std.time.milliTimestamp();
    const x = try e.removeField("UserName", time6);
    defer {
        allocator.free(x.?.key);
        allocator.free(x.?.value);
    }
    try std.testing.expect(x != null);
    const time7 = std.time.milliTimestamp();
    try std.testing.expectEqualSlices(u8, "https://ziglang.org", e.getField("URL", time7).?);
    try std.testing.expectEqual(time6, e.times.lastModificationTime);
    try std.testing.expectEqual(time, e.times.creationTime);
    try std.testing.expectEqual(time7, e.times.lastAccessTime);
    try std.testing.expectEqual(@as(usize, @intCast(1)), e.fields.?.len);
}

test "serialize entry" {
    const allocator = std.testing.allocator;

    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    var id = try allocator.alloc(u8, 64);
    @memcpy(id, "\x6a\x32\xdb\x1f\xff\x8d\xf0\x57\xb2\x85\xa9\x60\x0a\x2a\x2e\x1e\x61\x2b\xc4\xa9\x49\x3e\x8d\xf1\x6c\x31\x93\x04\x27\xad\x68\xc7\x24\x0b\x98\x4a\x8a\xf8\xaa\xf7\xe4\x53\x1f\x6c\x28\x97\xa9\x84\x6a\xc9\x74\x7a\xa3\x87\xea\xaf\xf0\xf6\x9a\x58\x36\x1f\x19\xdf");
    var e = @This().new(id, 0, allocator);
    defer e.deinit();
    try e.addField(.{ .key = "UserName", .value = "r4gus" }, 0);
    try e.addField(.{ .key = "URL", .value = "https://ziglang.org" }, 0);

    try cbor.stringify(e, .{}, str.writer());

    try std.testing.expectEqualSlices(u8, "\xa3\x62\x69\x64\x58\x40\x6a\x32\xdb\x1f\xff\x8d\xf0\x57\xb2\x85\xa9\x60\x0a\x2a\x2e\x1e\x61\x2b\xc4\xa9\x49\x3e\x8d\xf1\x6c\x31\x93\x04\x27\xad\x68\xc7\x24\x0b\x98\x4a\x8a\xf8\xaa\xf7\xe4\x53\x1f\x6c\x28\x97\xa9\x84\x6a\xc9\x74\x7a\xa3\x87\xea\xaf\xf0\xf6\x9a\x58\x36\x1f\x19\xdf\x65\x74\x69\x6d\x65\x73\xa4\x74\x6c\x61\x73\x74\x4d\x6f\x64\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6c\x63\x72\x65\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6e\x6c\x61\x73\x74\x41\x63\x63\x65\x73\x73\x54\x69\x6d\x65\x00\x6a\x75\x73\x61\x67\x65\x43\x6f\x75\x6e\x74\x00\x66\x66\x69\x65\x6c\x64\x73\x82\xa2\x63\x6b\x65\x79\x68\x55\x73\x65\x72\x4e\x61\x6d\x65\x65\x76\x61\x6c\x75\x65\x65\x72\x34\x67\x75\x73\xa2\x63\x6b\x65\x79\x63\x55\x52\x4c\x65\x76\x61\x6c\x75\x65\x73\x68\x74\x74\x70\x73\x3a\x2f\x2f\x7a\x69\x67\x6c\x61\x6e\x67\x2e\x6f\x72\x67", str.items);
}

test "deserialize entry" {
    const allocator = std.testing.allocator;

    var e = try cbor.parse(@This(), try cbor.DataItem.new("\xa3\x62\x69\x64\x58\x40\x6a\x32\xdb\x1f\xff\x8d\xf0\x57\xb2\x85\xa9\x60\x0a\x2a\x2e\x1e\x61\x2b\xc4\xa9\x49\x3e\x8d\xf1\x6c\x31\x93\x04\x27\xad\x68\xc7\x24\x0b\x98\x4a\x8a\xf8\xaa\xf7\xe4\x53\x1f\x6c\x28\x97\xa9\x84\x6a\xc9\x74\x7a\xa3\x87\xea\xaf\xf0\xf6\x9a\x58\x36\x1f\x19\xdf\x65\x74\x69\x6d\x65\x73\xa4\x74\x6c\x61\x73\x74\x4d\x6f\x64\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6c\x63\x72\x65\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6e\x6c\x61\x73\x74\x41\x63\x63\x65\x73\x73\x54\x69\x6d\x65\x00\x6a\x75\x73\x61\x67\x65\x43\x6f\x75\x6e\x74\x00\x66\x66\x69\x65\x6c\x64\x73\x82\xa2\x63\x6b\x65\x79\x68\x55\x73\x65\x72\x4e\x61\x6d\x65\x65\x76\x61\x6c\x75\x65\x65\x72\x34\x67\x75\x73\xa2\x63\x6b\x65\x79\x63\x55\x52\x4c\x65\x76\x61\x6c\x75\x65\x73\x68\x74\x74\x70\x73\x3a\x2f\x2f\x7a\x69\x67\x6c\x61\x6e\x67\x2e\x6f\x72\x67"), .{ .allocator = allocator });
    defer e.deinit();

    const time1 = std.time.milliTimestamp();
    try std.testing.expectEqualSlices(u8, "r4gus", e.getField("UserName", time1).?);
    try std.testing.expectEqualSlices(u8, "https://ziglang.org", e.getField("URL", time1).?);
    try std.testing.expectEqual(@as(i64, @intCast(0)), e.times.lastModificationTime);
    try std.testing.expectEqual(@as(i64, @intCast(0)), e.times.creationTime);
    try std.testing.expectEqual(time1, e.times.lastAccessTime);
    try std.testing.expectEqual(@as(usize, @intCast(2)), e.fields.?.len);
}
