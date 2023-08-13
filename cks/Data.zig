const std = @import("std");
const cbor = @import("zbor");
const Entry = @import("Entry.zig");

/// Name of the application that created this data
generator: []const u8,
/// Name of the database
name: []const u8,
/// Global times specific to all data
times: @import("Times.zig"),
/// List of database entries
entries: ?[]Entry = null,

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

pub fn new(generator: []const u8, name: []const u8, time: i64, allocator: std.mem.Allocator) @This() {
    return @This(){
        .generator = generator,
        .name = name,
        .times = .{
            .lastModificationTime = time,
            .creationTime = time,
            .lastAccessTime = time,
            .usageCount = 0,
        },
        .allocator = allocator,
    };
}

pub fn deinit(self: *const @This()) void {
    if (self.entries) |entries| {
        for (entries) |entry| {
            entry.deinit();
        }
        self.allocator.free(entries);
    }
}

pub fn addEntry(self: *@This(), entry: Entry, time: i64) !void {
    self.entries = if (self.entries) |entries| blk: {
        for (entries) |_entry| {
            if (std.mem.eql(u8, _entry.id, entry.id)) {
                return error.DoesExist;
            }
        }

        var new_mem = try self.allocator.alloc(Entry, entries.len + 1);
        @memcpy(new_mem[0..entries.len], entries);
        self.allocator.free(entries);
        break :blk new_mem;
    } else blk: {
        break :blk try self.allocator.alloc(Entry, 1);
    };
    // At this point self.entries is NOT null

    self.entries.?[self.entries.?.len - 1] = entry;
    self.times.lastModificationTime = time;
}

pub fn getEntry(self: *@This(), id: []const u8, time: i64) ?*Entry {
    if (self.entries) |entries| {
        self.times.lastAccessTime = time;
        for (entries) |*entry| {
            if (std.mem.eql(u8, entry.id, id)) {
                return entry;
            }
        }
    }
    return null;
}

pub const Filter = struct {
    key: []const u8,
    value: []const u8,
};

pub fn getEntries(
    self: *@This(),
    filters: []const Filter,
    allocator: std.mem.Allocator,
    time: i64,
) ?[]const *Entry {
    var arr = std.ArrayList(*Entry).init(allocator);

    if (self.entries) |entries| {
        self.times.lastAccessTime = time;
        outer_blk: for (entries) |*entry| {
            for (filters) |*filter| {
                if (entry.getField(filter.key, time)) |v| {
                    if (!std.mem.eql(u8, filter.value, v)) {
                        continue :outer_blk;
                    }
                } else {
                    continue :outer_blk;
                }
            }

            arr.append(entry) catch {
                arr.deinit();
                return null;
            };
        }

        if (arr.items.len > 0) {
            return arr.toOwnedSlice() catch unreachable;
        } else {
            arr.deinit();
            return null;
        }
    }
    return null;
}

pub fn removeEntry(self: *@This(), id: []const u8, time: i64) !Entry {
    if (self.entries) |entries| {
        var i: usize = 0;
        for (entries) |entry| {
            if (std.mem.eql(u8, entry.id, id)) {
                var e = entry;
                var new_mem = try self.allocator.alloc(Entry, entries.len - 1);
                @memcpy(new_mem[0..i], entries[0..i]);
                @memcpy(new_mem[i..], entries[i + 1 ..]);
                self.allocator.free(self.entries.?);
                self.entries = new_mem;
                self.times.lastModificationTime = time;
                return e;
            }
            i += 1;
        }
    }
    return error.DoesNotExist;
}

test "data tests" {
    _ = Entry;
}

test "create Data struct and add two entries" {
    const allocator = std.testing.allocator;
    const time = std.time.milliTimestamp();

    var d = @This().new("PassKeyXC", "DB1", time, allocator);
    defer d.deinit();
    try std.testing.expectEqual(time, d.times.lastModificationTime);
    try std.testing.expectEqual(time, d.times.creationTime);
    try std.testing.expectEqual(time, d.times.lastAccessTime);
    try std.testing.expectEqual(d.times.usageCount, 0);

    // Add first entry
    var id1 = try allocator.alloc(u8, 64);
    const time1 = std.time.milliTimestamp();
    std.crypto.random.bytes(id1[0..]);
    var e1 = Entry.new(id1, time1, allocator);
    try e1.addField(.{ .key = "UserName", .value = "r4gus" }, time1);
    try e1.addField(.{ .key = "URL", .value = "https://ziglang.org" }, time1);

    const time2 = std.time.milliTimestamp();
    try d.addEntry(e1, time2);
    try std.testing.expectEqual(time2, d.times.lastModificationTime);
    try std.testing.expectEqual(time, d.times.creationTime);
    try std.testing.expectEqual(time, d.times.lastAccessTime);
    try std.testing.expectEqual(d.times.usageCount, 0);
    try std.testing.expectEqual(@as(usize, @intCast(1)), d.entries.?.len);

    // Add second entry
    var id2 = try allocator.alloc(u8, 64);
    const time3 = std.time.milliTimestamp();
    std.crypto.random.bytes(id2[0..]);
    var e2 = Entry.new(id2, time3, allocator);
    try e2.addField(.{ .key = "UserName", .value = "SugarYourCoffee" }, time1);
    try e2.addField(.{ .key = "URL", .value = "https://sugaryourcoffee.de" }, time1);

    const time4 = std.time.milliTimestamp();
    try d.addEntry(e2, time4);
    try std.testing.expectEqual(time4, d.times.lastModificationTime);
    try std.testing.expectEqual(time, d.times.creationTime);
    try std.testing.expectEqual(time, d.times.lastAccessTime);
    try std.testing.expectEqual(d.times.usageCount, 0);
    try std.testing.expectEqual(@as(usize, @intCast(2)), d.entries.?.len);

    // Get the first entry
    const time5 = std.time.milliTimestamp();
    var e3 = d.getEntry(id1, time5);
    try std.testing.expect(e3 != null);
    try std.testing.expectEqualSlices(u8, "r4gus", e3.?.getField("UserName", time5).?);
    try std.testing.expectEqualSlices(u8, "https://ziglang.org", e3.?.getField("URL", time5).?);
    try std.testing.expectEqual(time4, d.times.lastModificationTime);
    try std.testing.expectEqual(time, d.times.creationTime);
    try std.testing.expectEqual(time5, d.times.lastAccessTime);
    try std.testing.expectEqual(d.times.usageCount, 0);
    try std.testing.expectEqual(@as(usize, @intCast(2)), d.entries.?.len);

    // Remove first entry
    // e3 pointer is invalid after the removal!
    const time6 = std.time.milliTimestamp();
    var e4 = try d.removeEntry(id1, time6);
    defer e4.deinit();
    try std.testing.expectEqualSlices(u8, "r4gus", e4.getField("UserName", time5).?);
    try std.testing.expectEqualSlices(u8, "https://ziglang.org", e4.getField("URL", time5).?);
    try std.testing.expectEqual(@as(usize, @intCast(1)), d.entries.?.len);

    e3 = d.getEntry(id1, time6);
    try std.testing.expect(e3 == null);
    e3 = d.getEntry(id2, time6);
    try std.testing.expect(e3 != null);
    try std.testing.expectEqualSlices(u8, "SugarYourCoffee", e3.?.getField("UserName", time5).?);
    try std.testing.expectEqualSlices(u8, "https://sugaryourcoffee.de", e3.?.getField("URL", time5).?);

    // Remove second entry
    const time7 = std.time.milliTimestamp();
    var e5 = try d.removeEntry(id2, time7);
    defer e5.deinit();
    try std.testing.expectEqualSlices(u8, "SugarYourCoffee", e5.getField("UserName", time5).?);
    try std.testing.expectEqualSlices(u8, "https://sugaryourcoffee.de", e5.getField("URL", time5).?);
    try std.testing.expectEqual(@as(usize, @intCast(0)), d.entries.?.len);
}

test "serialize data" {
    const allocator = std.testing.allocator;

    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    var d = @This().new("PassKeyXC", "DB1", 0, allocator);
    defer d.deinit();

    var id1 = try allocator.alloc(u8, 64);
    @memcpy(id1, "\x6a\x32\xdb\x1f\xff\x8d\xf0\x57\xb2\x85\xa9\x60\x0a\x2a\x2e\x1e\x61\x2b\xc4\xa9\x49\x3e\x8d\xf1\x6c\x31\x93\x04\x27\xad\x68\xc7\x24\x0b\x98\x4a\x8a\xf8\xaa\xf7\xe4\x53\x1f\x6c\x28\x97\xa9\x84\x6a\xc9\x74\x7a\xa3\x87\xea\xaf\xf0\xf6\x9a\x58\x36\x1f\x19\xdf");
    var e1 = Entry.new(id1, 0, allocator);
    try e1.addField(.{ .key = "UserName", .value = "r4gus" }, 0);
    try e1.addField(.{ .key = "URL", .value = "https://ziglang.org" }, 0);

    var id2 = try allocator.alloc(u8, 64);
    @memcpy(id2, "\x6b\x32\xdb\x1f\xff\x8d\xf0\x57\xb2\x85\xa9\x60\x0a\x2a\x2e\x1e\x61\x2b\xc4\xa9\x49\x3e\x8d\xf1\x6c\x31\x93\x04\x27\xad\x68\xc7\x24\x0b\x98\x4a\x8a\xf8\xaa\xf7\xe4\x53\x1f\x6c\x28\x97\xa9\x84\x6a\xc9\x74\x7a\xa3\x87\xea\xaf\xf0\xf6\x9a\x58\x36\x1f\x19\xdf");
    var e2 = Entry.new(id2, 0, allocator);
    try e2.addField(.{ .key = "UserName", .value = "SugarYourCoffee" }, 0);
    try e2.addField(.{ .key = "URL", .value = "https://sugaryourcoffee.de" }, 0);

    try d.addEntry(e1, 0);
    try d.addEntry(e2, 0);

    try cbor.stringify(d, .{}, str.writer());

    try std.testing.expectEqualSlices(u8, "\xa4\x69\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x69\x50\x61\x73\x73\x4b\x65\x79\x58\x43\x64\x6e\x61\x6d\x65\x63\x44\x42\x31\x65\x74\x69\x6d\x65\x73\xa4\x74\x6c\x61\x73\x74\x4d\x6f\x64\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6c\x63\x72\x65\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6e\x6c\x61\x73\x74\x41\x63\x63\x65\x73\x73\x54\x69\x6d\x65\x00\x6a\x75\x73\x61\x67\x65\x43\x6f\x75\x6e\x74\x00\x67\x65\x6e\x74\x72\x69\x65\x73\x82\xa3\x62\x69\x64\x58\x40\x6a\x32\xdb\x1f\xff\x8d\xf0\x57\xb2\x85\xa9\x60\x0a\x2a\x2e\x1e\x61\x2b\xc4\xa9\x49\x3e\x8d\xf1\x6c\x31\x93\x04\x27\xad\x68\xc7\x24\x0b\x98\x4a\x8a\xf8\xaa\xf7\xe4\x53\x1f\x6c\x28\x97\xa9\x84\x6a\xc9\x74\x7a\xa3\x87\xea\xaf\xf0\xf6\x9a\x58\x36\x1f\x19\xdf\x65\x74\x69\x6d\x65\x73\xa4\x74\x6c\x61\x73\x74\x4d\x6f\x64\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6c\x63\x72\x65\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6e\x6c\x61\x73\x74\x41\x63\x63\x65\x73\x73\x54\x69\x6d\x65\x00\x6a\x75\x73\x61\x67\x65\x43\x6f\x75\x6e\x74\x00\x66\x66\x69\x65\x6c\x64\x73\x82\xa2\x63\x6b\x65\x79\x68\x55\x73\x65\x72\x4e\x61\x6d\x65\x65\x76\x61\x6c\x75\x65\x65\x72\x34\x67\x75\x73\xa2\x63\x6b\x65\x79\x63\x55\x52\x4c\x65\x76\x61\x6c\x75\x65\x73\x68\x74\x74\x70\x73\x3a\x2f\x2f\x7a\x69\x67\x6c\x61\x6e\x67\x2e\x6f\x72\x67\xa3\x62\x69\x64\x58\x40\x6b\x32\xdb\x1f\xff\x8d\xf0\x57\xb2\x85\xa9\x60\x0a\x2a\x2e\x1e\x61\x2b\xc4\xa9\x49\x3e\x8d\xf1\x6c\x31\x93\x04\x27\xad\x68\xc7\x24\x0b\x98\x4a\x8a\xf8\xaa\xf7\xe4\x53\x1f\x6c\x28\x97\xa9\x84\x6a\xc9\x74\x7a\xa3\x87\xea\xaf\xf0\xf6\x9a\x58\x36\x1f\x19\xdf\x65\x74\x69\x6d\x65\x73\xa4\x74\x6c\x61\x73\x74\x4d\x6f\x64\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6c\x63\x72\x65\x61\x74\x69\x6f\x6e\x54\x69\x6d\x65\x00\x6e\x6c\x61\x73\x74\x41\x63\x63\x65\x73\x73\x54\x69\x6d\x65\x00\x6a\x75\x73\x61\x67\x65\x43\x6f\x75\x6e\x74\x00\x66\x66\x69\x65\x6c\x64\x73\x82\xa2\x63\x6b\x65\x79\x68\x55\x73\x65\x72\x4e\x61\x6d\x65\x65\x76\x61\x6c\x75\x65\x6f\x53\x75\x67\x61\x72\x59\x6f\x75\x72\x43\x6f\x66\x66\x65\x65\xa2\x63\x6b\x65\x79\x63\x55\x52\x4c\x65\x76\x61\x6c\x75\x65\x78\x1a\x68\x74\x74\x70\x73\x3a\x2f\x2f\x73\x75\x67\x61\x72\x79\x6f\x75\x72\x63\x6f\x66\x66\x65\x65\x2e\x64\x65", str.items);
}
