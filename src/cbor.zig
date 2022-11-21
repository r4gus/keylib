const std = @import("std");

pub const Error = error{ Malformed, TypeMismatch, UnsupportedType };

pub const Type = enum {
    Int,
    ByteString,
    TextString,
    Array,
    Map,
    False,
    True,
    Null,
    Undefined,
    Simple,
    Tagged,
    Float,
    UnsignedBignum,
    Unknown,

    pub fn fromByte(b: u8) @This() {
        return switch (b) {
            0x00...0x3b => .Int,
            0x40...0x5b => .ByteString,
            0x60...0x7b => .TextString,
            0x80...0x9b => .Array,
            0xa0...0xbb => .Map,
            0xf4 => .False,
            0xf5 => .True,
            0xf6 => .Null,
            0xf7 => .Undefined,
            0xe0...0xf3, 0xf8 => .Simple,
            0xc0...0xdb => .Tagged,
            0xf9...0xfb => .Float,
            else => .Unknown,
        };
    }
};

pub const DataItem = struct {
    data: []const u8,

    pub fn new(data: []const u8) @This() {
        return .{ .data = data };
    }

    pub fn getType(self: @This()) Type {
        return Type.fromByte(self.data[0]);
    }

    pub fn int(self: @This()) ?i65 {
        if (self.data[0] <= 0x1b and self.data[0] >= 0x00) {
            return @intCast(i65, if (additionalInfo(self.data, null)) |v| v else return null);
        } else if (self.data[0] <= 0x3b and self.data[0] >= 0x20) {
            return -@intCast(i65, if (additionalInfo(self.data, null)) |v| v else return null) - 1;
        } else {
            return null;
        }
    }

    pub fn string(self: @This()) ?[]const u8 {
        if (!(self.data[0] <= 0x5b and self.data[0] >= 0x40) and !(self.data[0] <= 0x7b and self.data[0] >= 0x60)) return null;

        var begin: usize = 0;
        var len = if (additionalInfo(self.data, &begin)) |v| @intCast(usize, v) else return null;

        if (@intCast(u65, begin) + @intCast(u65, len) > self.data.len) return null;
        return self.data[begin .. begin + len];
    }

    pub fn array(self: @This()) ?ArrayIterator {
        if (self.data[0] > 0x9b or self.data[0] < 0x80) return null;

        var begin: usize = 0;
        var len = if (additionalInfo(self.data, &begin)) |v| @intCast(usize, v) else return null;

        // Get to the end of the array
        var end: usize = 0;
        if (burn(self.data, &end) == null) return null;

        return ArrayIterator{
            .data = self.data[begin..end],
            .len = len,
            .count = 0,
            .i = 0,
        };
    }

    pub fn map(self: @This()) ?MapIterator {
        if (self.data[0] > 0xbb or self.data[0] < 0xa0) return null;

        var begin: usize = 0;
        var len = if (additionalInfo(self.data, &begin)) |v| @intCast(usize, v) else return null;

        // Get to the end of the map
        var end: usize = 0;
        if (burn(self.data, &end) == null) return null;

        return MapIterator{
            .data = self.data[begin..end],
            .len = len,
            .count = 0,
            .i = 0,
        };
    }

    pub fn simple(self: @This()) ?u8 {
        return switch (self.data[0]) {
            0xe0...0xf3 => self.data[0] & 0x1f,
            0xf8 => self.data[1],
            else => null,
        };
    }

    pub fn float(self: @This()) ?f64 {
        if (self.data[0] > 0xfb or self.data[0] < 0xf9) return null;

        if (additionalInfo(self.data, null)) |v| {
            return switch (self.data[0]) {
                0xf9 => @floatCast(f64, @bitCast(f16, @intCast(u16, v))),
                0xfa => @floatCast(f64, @bitCast(f32, @intCast(u32, v))),
                0xfb => @bitCast(f64, v),
                else => unreachable,
            };
        } else {
            return null;
        }
    }

    pub fn tagged(self: @This()) ?Tag {
        if (self.data[0] > 0xdb or self.data[0] < 0xc0) return null;

        var begin: usize = 0;
        var nr = if (additionalInfo(self.data, &begin)) |v| v else return null;

        return Tag{ .nr = nr, .content = DataItem.new(self.data[begin..]) };
    }
};

pub const Tag = struct {
    nr: u64,
    content: DataItem,
};

pub const Pair = struct {
    key: DataItem,
    value: DataItem,
};

pub const MapIterator = struct {
    data: []const u8,
    len: usize,
    count: usize,
    i: usize,

    pub fn next(self: *@This()) ?Pair {
        if (self.count >= self.len) return null;
        var new_i: usize = self.i;

        if (burn(self.data, &new_i) == null) return null;
        const k = DataItem.new(self.data[self.i..new_i]);
        self.i = new_i;

        if (burn(self.data, &new_i) == null) return null;
        const v = DataItem.new(self.data[self.i..new_i]);
        self.i = new_i;

        self.count += 1;
        return Pair{ .key = k, .value = v };
    }
};

pub const ArrayIterator = struct {
    data: []const u8,
    len: usize,
    count: usize,
    i: usize,

    pub fn next(self: *@This()) ?DataItem {
        if (self.count >= self.len) return null;

        var new_i: usize = self.i;
        if (burn(self.data, &new_i) == null) return null;

        const tmp = self.data[self.i..new_i];
        self.i = new_i;
        self.count += 1;
        return DataItem.new(tmp);
    }
};

/// Move the index `i` to the beginning of the next data item.
fn burn(data: []const u8, i: *usize) ?void {
    var offset: usize = 0;
    const len = if (additionalInfo(data[i.*..], &offset)) |v| @intCast(usize, v) else return null;

    switch (data[i.*]) {
        0x00...0x1b => i.* += offset,
        0x20...0x3b => i.* += offset,
        0x40...0x5b => i.* += offset + len,
        0x60...0x7b => i.* += offset + len,
        0x80...0x9b => {
            i.* += offset;
            var x: usize = 0;
            while (x < len) : (x += 1) {
                if (burn(data, i) == null) {
                    return null;
                }
            }
        },
        0xa0...0xbb => {
            i.* += offset;
            var x: usize = 0;
            while (x < len) : (x += 1) {
                // this is NOT redundant!!!
                if (burn(data, i) == null or burn(data, i) == null) {
                    return null;
                }
            }
        },
        0xc0...0xdb => {
            i.* += offset;
            if (burn(data, i) == null) return null;
        },
        0xe0...0xfb => i.* += offset,
        else => return null,
    }
}

/// Return the additional information of the given data item.
///
/// Pass a reference to `l` if you want to know where the
/// actual data begins (|head| + |additional information|).
fn additionalInfo(data: []const u8, l: ?*usize) ?u64 {
    if (data.len < 1) return null;

    switch (data[0] & 0x1f) {
        0x00...0x17 => {
            if (l != null) l.?.* = 1;
            return @intCast(u64, data[0] & 0x1f);
        },
        0x18 => {
            if (data.len < 2) return null;
            if (l != null) l.?.* = 2;
            return @intCast(u64, data[1]);
        },
        0x19 => {
            if (data.len < 3) return null;
            if (l != null) l.?.* = 3;
            return @intCast(u64, unsigned_16(data[1..3]));
        },
        0x1a => {
            if (data.len < 5) return null;
            if (l != null) l.?.* = 5;
            return @intCast(u64, unsigned_32(data[1..5]));
        },
        0x1b => {
            if (data.len < 9) return null;
            if (l != null) l.?.* = 9;
            return @intCast(u64, unsigned_64(data[1..9]));
        },
        else => return null,
    }
}

pub fn unsigned_16(data: []const u8) u16 {
    return @intCast(u16, data[0]) << 8 | @intCast(u16, data[1]);
}

pub fn unsigned_32(data: []const u8) u32 {
    return @intCast(u32, data[0]) << 24 | @intCast(u32, data[1]) << 16 | @intCast(u32, data[2]) << 8 | @intCast(u32, data[3]);
}

pub fn unsigned_64(data: []const u8) u64 {
    return @intCast(u64, data[0]) << 56 | @intCast(u64, data[1]) << 48 | @intCast(u64, data[2]) << 40 | @intCast(u64, data[3]) << 32 | @intCast(u64, data[4]) << 24 | @intCast(u64, data[5]) << 16 | @intCast(u64, data[6]) << 8 | @intCast(u64, data[7]);
}

pub fn encode_2(cbor: anytype, head: u8, v: u64) !void {
    try cbor.writeByte(head | 25);
    try cbor.writeByte(@intCast(u8, (v >> 8) & 0xff));
    try cbor.writeByte(@intCast(u8, v & 0xff));
}

pub fn encode_4(cbor: anytype, head: u8, v: u64) !void {
    try cbor.writeByte(head | 26);
    try cbor.writeByte(@intCast(u8, (v >> 24) & 0xff));
    try cbor.writeByte(@intCast(u8, (v >> 16) & 0xff));
    try cbor.writeByte(@intCast(u8, (v >> 8) & 0xff));
    try cbor.writeByte(@intCast(u8, v & 0xff));
}

pub fn encode_8(cbor: anytype, head: u8, v: u64) !void {
    try cbor.writeByte(head | 27);
    try cbor.writeByte(@intCast(u8, (v >> 56) & 0xff));
    try cbor.writeByte(@intCast(u8, (v >> 48) & 0xff));
    try cbor.writeByte(@intCast(u8, (v >> 40) & 0xff));
    try cbor.writeByte(@intCast(u8, (v >> 32) & 0xff));
    try cbor.writeByte(@intCast(u8, (v >> 24) & 0xff));
    try cbor.writeByte(@intCast(u8, (v >> 16) & 0xff));
    try cbor.writeByte(@intCast(u8, (v >> 8) & 0xff));
    try cbor.writeByte(@intCast(u8, v & 0xff));
}

test "deserialize unsigned" {
    const di1 = DataItem.new("\x00");
    try std.testing.expectEqual(Type.Int, di1.getType());
    try std.testing.expectEqual(di1.int().?, 0);

    const di2 = DataItem.new("\x01");
    try std.testing.expectEqual(Type.Int, di2.getType());
    try std.testing.expectEqual(di2.int().?, 1);

    const di3 = DataItem.new("\x17");
    try std.testing.expectEqual(Type.Int, di3.getType());
    try std.testing.expectEqual(di3.int().?, 23);

    const di4 = DataItem.new("\x18\x18");
    try std.testing.expectEqual(Type.Int, di4.getType());
    try std.testing.expectEqual(di4.int().?, 24);

    const di5 = DataItem.new("\x18\x64");
    try std.testing.expectEqual(Type.Int, di5.getType());
    try std.testing.expectEqual(di5.int().?, 100);

    const di6 = DataItem.new("\x19\x03\xe8");
    try std.testing.expectEqual(Type.Int, di6.getType());
    try std.testing.expectEqual(di6.int().?, 1000);

    const di7 = DataItem.new("\x1a\x00\x0f\x42\x40");
    try std.testing.expectEqual(Type.Int, di7.getType());
    try std.testing.expectEqual(di7.int().?, 1000000);

    const di8 = DataItem.new("\x1b\x00\x00\x00\xe8\xd4\xa5\x10\x00");
    try std.testing.expectEqual(Type.Int, di8.getType());
    try std.testing.expectEqual(di8.int().?, 1000000000000);

    const di9 = DataItem.new("\x1b\xff\xff\xff\xff\xff\xff\xff\xff");
    try std.testing.expectEqual(Type.Int, di9.getType());
    try std.testing.expectEqual(di9.int().?, 18446744073709551615);
}

test "deserialize negative" {
    const di1 = DataItem.new("\x20");
    try std.testing.expectEqual(Type.Int, di1.getType());
    try std.testing.expectEqual(di1.int().?, -1);

    const di2 = DataItem.new("\x29");
    try std.testing.expectEqual(Type.Int, di2.getType());
    try std.testing.expectEqual(di2.int().?, -10);

    const di3 = DataItem.new("\x38\x63");
    try std.testing.expectEqual(Type.Int, di3.getType());
    try std.testing.expectEqual(di3.int().?, -100);

    const di6 = DataItem.new("\x39\x03\xe7");
    try std.testing.expectEqual(Type.Int, di6.getType());
    try std.testing.expectEqual(di6.int().?, -1000);

    const di9 = DataItem.new("\x3b\xff\xff\xff\xff\xff\xff\xff\xff");
    try std.testing.expectEqual(Type.Int, di9.getType());
    try std.testing.expectEqual(di9.int().?, -18446744073709551616);
}

test "deserialize byte string" {
    const di1 = DataItem.new("\x40");
    try std.testing.expectEqual(Type.ByteString, di1.getType());
    try std.testing.expectEqualSlices(u8, di1.string().?, "");

    const di2 = DataItem.new("\x44\x01\x02\x03\x04");
    try std.testing.expectEqual(Type.ByteString, di2.getType());
    try std.testing.expectEqualSlices(u8, di2.string().?, "\x01\x02\x03\x04");
}

test "deserialize text string" {
    const di1 = DataItem.new("\x60");
    try std.testing.expectEqual(Type.TextString, di1.getType());
    try std.testing.expectEqualStrings(di1.string().?, "");

    const di2 = DataItem.new("\x61\x61");
    try std.testing.expectEqual(Type.TextString, di2.getType());
    try std.testing.expectEqualStrings(di2.string().?, "a");

    const di3 = DataItem.new("\x64\x49\x45\x54\x46");
    try std.testing.expectEqual(Type.TextString, di3.getType());
    try std.testing.expectEqualStrings(di3.string().?, "IETF");

    const di4 = DataItem.new("\x62\x22\x5c");
    try std.testing.expectEqual(Type.TextString, di4.getType());
    try std.testing.expectEqualStrings(di4.string().?, "\"\\");

    const di5 = DataItem.new("\x62\xc3\xbc");
    try std.testing.expectEqual(Type.TextString, di5.getType());
    try std.testing.expectEqualStrings(di5.string().?, "ü");

    const di6 = DataItem.new("\x63\xe6\xb0\xb4");
    try std.testing.expectEqual(Type.TextString, di6.getType());
    try std.testing.expectEqualStrings(di6.string().?, "水");
}

test "deserialize array" {
    const di1 = DataItem.new("\x80");
    try std.testing.expectEqual(Type.Array, di1.getType());
    var ai1 = di1.array().?;
    try std.testing.expectEqual(ai1.next(), null);
    try std.testing.expectEqual(ai1.next(), null);

    const di2 = DataItem.new("\x83\x01\x02\x03");
    try std.testing.expectEqual(Type.Array, di2.getType());
    var ai2 = di2.array().?;
    try std.testing.expectEqual(ai2.next().?.int().?, 1);
    try std.testing.expectEqual(ai2.next().?.int().?, 2);
    try std.testing.expectEqual(ai2.next().?.int().?, 3);
    try std.testing.expectEqual(ai2.next(), null);

    const di3 = DataItem.new("\x98\x19\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x18\x18\x19");
    try std.testing.expectEqual(Type.Array, di3.getType());
    var ai3 = di3.array().?;
    var i: u64 = 1;
    while (i <= 25) : (i += 1) {
        try std.testing.expectEqual(ai3.next().?.int().?, i);
    }
    try std.testing.expectEqual(ai3.next(), null);

    const di4 = DataItem.new("\x83\x01\x82\x02\x03\x82\x04\x05");
    try std.testing.expectEqual(Type.Array, di4.getType());
    var ai4 = di4.array().?;
    try std.testing.expectEqual(ai4.next().?.int().?, 1);
    var ai4_1 = ai4.next().?.array().?;
    try std.testing.expectEqual(ai4_1.next().?.int().?, 2);
    try std.testing.expectEqual(ai4_1.next().?.int().?, 3);
    try std.testing.expectEqual(ai4_1.next(), null);
    var ai4_2 = ai4.next().?.array().?;
    try std.testing.expectEqual(ai4_2.next().?.int().?, 4);
    try std.testing.expectEqual(ai4_2.next().?.int().?, 5);
    try std.testing.expectEqual(ai4_2.next(), null);
    try std.testing.expectEqual(ai4.next(), null);
}

test "deserialize map" {
    const di1 = DataItem.new("\xa0");
    try std.testing.expectEqual(Type.Map, di1.getType());
    var ai1 = di1.map().?;
    try std.testing.expectEqual(ai1.next(), null);
    try std.testing.expectEqual(ai1.next(), null);

    const di2 = DataItem.new("\xa2\x01\x02\x03\x04");
    try std.testing.expectEqual(Type.Map, di2.getType());
    var ai2 = di2.map().?;
    const kv1 = ai2.next().?;
    try std.testing.expectEqual(kv1.key.int().?, 1);
    try std.testing.expectEqual(kv1.value.int().?, 2);
    const kv2 = ai2.next().?;
    try std.testing.expectEqual(kv2.key.int().?, 3);
    try std.testing.expectEqual(kv2.value.int().?, 4);
    try std.testing.expectEqual(ai2.next(), null);

    const di3 = DataItem.new("\xa2\x61\x61\x01\x61\x62\x82\x02\x03");
    try std.testing.expectEqual(Type.Map, di3.getType());
    var ai3 = di3.map().?;
    const kv1_2 = ai3.next().?;
    try std.testing.expectEqualStrings("a", kv1_2.key.string().?);
    try std.testing.expectEqual(kv1_2.value.int().?, 1);
    const kv2_2 = ai3.next().?;
    try std.testing.expectEqualStrings("b", kv2_2.key.string().?);
    var ai3_1 = kv2_2.value.array().?;
    try std.testing.expectEqual(ai3_1.next().?.int().?, 2);
    try std.testing.expectEqual(ai3_1.next().?.int().?, 3);
    try std.testing.expectEqual(ai3_1.next(), null);
    try std.testing.expectEqual(ai3.next(), null);
}

test "deserialize other" {
    const di1 = DataItem.new("\x82\x61\x61\xa1\x61\x62\x61\x63");
    try std.testing.expectEqual(Type.Array, di1.getType());
    var ai1 = di1.array().?;
    try std.testing.expectEqualStrings("a", ai1.next().?.string().?);
    var m1 = ai1.next().?.map().?;
    var kv1 = m1.next().?;
    try std.testing.expectEqualStrings("b", kv1.key.string().?);
    try std.testing.expectEqualStrings("c", kv1.value.string().?);
}

test "deserialize simple" {
    const di1 = DataItem.new("\xf4");
    try std.testing.expectEqual(Type.False, di1.getType());

    const di2 = DataItem.new("\xf5");
    try std.testing.expectEqual(Type.True, di2.getType());

    const di3 = DataItem.new("\xf6");
    try std.testing.expectEqual(Type.Null, di3.getType());

    const di4 = DataItem.new("\xf7");
    try std.testing.expectEqual(Type.Undefined, di4.getType());

    const di5 = DataItem.new("\xf0");
    try std.testing.expectEqual(Type.Simple, di5.getType());
    try std.testing.expectEqual(di5.simple().?, 16);

    const di6 = DataItem.new("\xf8\xff");
    try std.testing.expectEqual(Type.Simple, di6.getType());
    try std.testing.expectEqual(di6.simple().?, 255);
}

test "deserialize float" {
    const di1 = DataItem.new("\xfb\x3f\xf1\x99\x99\x99\x99\x99\x9a");
    try std.testing.expectEqual(Type.Float, di1.getType());
    try std.testing.expectApproxEqAbs(di1.float().?, 1.1, 0.000000001);

    const di2 = DataItem.new("\xf9\x3e\x00");
    try std.testing.expectEqual(Type.Float, di2.getType());
    try std.testing.expectApproxEqAbs(di2.float().?, 1.5, 0.000000001);

    const di3 = DataItem.new("\xf9\x80\x00");
    try std.testing.expectEqual(Type.Float, di3.getType());
    try std.testing.expectApproxEqAbs(di3.float().?, -0.0, 0.000000001);

    const di4 = DataItem.new("\xfb\x7e\x37\xe4\x3c\x88\x00\x75\x9c");
    try std.testing.expectEqual(Type.Float, di4.getType());
    try std.testing.expectApproxEqAbs(di4.float().?, 1.0e+300, 0.000000001);
}

test "deserialize tagged" {
    const di1 = DataItem.new("\xc0\x74\x32\x30\x31\x33\x2d\x30\x33\x2d\x32\x31\x54\x32\x30\x3a\x30\x34\x3a\x30\x30\x5a");
    try std.testing.expectEqual(Type.Tagged, di1.getType());
    const t1 = di1.tagged().?;
    try std.testing.expectEqual(t1.nr, 0);
}

test "definite-length strings with short data" {
    const di1 = DataItem.new("\x41");
    try std.testing.expectEqual(Type.ByteString, di1.getType());
    try std.testing.expectEqual(di1.string(), null);

    const di2 = DataItem.new("\x61");
    try std.testing.expectEqual(Type.TextString, di2.getType());
    try std.testing.expectEqual(di2.string(), null);

    const di3 = DataItem.new("\x5a\xff\xff\xff\xff\x00");
    try std.testing.expectEqual(Type.ByteString, di3.getType());
    try std.testing.expectEqual(di3.string(), null);

    const di4 = DataItem.new("\x5b\xff\xff\xff\xff\xff\xff\xff\xff\x01\x02\x03");
    try std.testing.expectEqual(Type.ByteString, di4.getType());
    try std.testing.expectEqual(di4.string(), null);

    const di5 = DataItem.new("\x7a\xff\xff\xff\xff\x00");
    try std.testing.expectEqual(Type.TextString, di5.getType());
    try std.testing.expectEqual(di5.string(), null);

    const di6 = DataItem.new("\x7b\x7f\xff\xff\xff\xff\xff\xff\xff\x01\x02\x03");
    try std.testing.expectEqual(Type.TextString, di6.getType());
    try std.testing.expectEqual(di6.string(), null);
}

test "definite-length maps and arrays not closed with enough items" {
    const di1 = DataItem.new("\x81");
    try std.testing.expectEqual(Type.Array, di1.getType());
    try std.testing.expectEqual(di1.array(), null);

    const di2 = DataItem.new("\x81\x81\x81\x81\x81\x81\x81\x81\x81");
    try std.testing.expectEqual(Type.Array, di2.getType());
    try std.testing.expectEqual(di2.array(), null);

    const di3 = DataItem.new("\x82\x00");
    try std.testing.expectEqual(Type.Array, di3.getType());
    try std.testing.expectEqual(di3.array(), null);

    const di4 = DataItem.new("\xa1");
    try std.testing.expectEqual(Type.Map, di4.getType());
    try std.testing.expectEqual(di4.map(), null);

    const di5 = DataItem.new("\xa2\x01\x02");
    try std.testing.expectEqual(Type.Map, di5.getType());
    try std.testing.expectEqual(di5.map(), null);

    const di6 = DataItem.new("\xa1\x00");
    try std.testing.expectEqual(Type.Map, di6.getType());
    try std.testing.expectEqual(di6.map(), null);

    const di7 = DataItem.new("\xa2\x00\x00\x00");
    try std.testing.expectEqual(Type.Map, di7.getType());
    try std.testing.expectEqual(di7.map(), null);
}
